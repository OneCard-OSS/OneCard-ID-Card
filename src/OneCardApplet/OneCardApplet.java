/*
 * 파일명: OneCardApplet.java
 * 애플릿을 스마트카드에 설치하기 위해서는 설치 파라미터로
 * 1이상 32 이하 길이의 사용자 식별자 Length-Value 형식으로 전달하여야 합니다.
 * 예) 사번 문자열 "1234"을 사용자 식별자로 사용하려는 경우 설치 파라미터로 "04 49 50 51 52" 전달
 */

package OneCardApplet;

import javacard.framework.*;
import javacard.security.*;
import javacard.security.KeyBuilder;
import javacardx.crypto.*;

public class OneCardApplet extends Applet {

    // CLA 바이트 정의
    private static final byte CLA_ONECARD_COMMON = (byte) 0xFF;

    // 인증 및 보안 명령 정의
    private static final byte INS_GET_CARD_INFO = (byte) 0xA0;
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0xA1;
    private static final byte INS_EXT_AUTHENTICATE = (byte) 0xA3;
    private static final byte INS_INIT_OWNERPIN = (byte) 0x10;
    private static final byte INS_CHANGE_OWNERPIN = (byte) 0x11;

    // 가독성을 위한 상수 정의
    private static final short OFFSET_TAG = 0;
    private static final short OFFSET_LENGTH = 1;
    private static final short OFFSET_VALUE = 2;
    private static final short OFFSET_LV_LENGTH = 0;
    private static final short OFFSET_LV_VALUE = 1;
    private static final byte TAG_OWNER_ID = (byte) 0x49;
    private static final byte TAG_PIN_STATUS = (byte) 0x50;

    // 상수 정의
    private static final byte OWNER_DETAILS_MAX = 32;
    private static final byte MIN_PIN_SIZE = 4;
    private static final byte MAX_PIN_SIZE = 8;
    private static final byte PIN_TRY_LIMIT = 6;
    private static final byte[] PIN_PASSED_FLAG = new byte[] {
            TAG_PIN_STATUS,
            (byte) 0x01,
            (byte) 0x01,
    };

    // 인증 관련 상수
    private static final short HOST_PUBKEY_LENGTH = 65;
    private static final short CHALLENGE_LENGTH = 16;
    private static final short MIN_APDU_LEN_NO_PIN =
            HOST_PUBKEY_LENGTH + CHALLENGE_LENGTH;
    private static final short MIN_APDU_LEN_WITH_PIN =
            MIN_APDU_LEN_NO_PIN + 2 + MIN_PIN_SIZE;
    private static final short MAX_APDU_LEN_WITH_PIN =
            MIN_APDU_LEN_NO_PIN + 2 + MAX_PIN_SIZE;

    // ECDH 관련 상수 추가
    private static final short SHARED_SECRET_LENGTH = 32;

    // 영속 저장 변수(Flash)
    private byte[] ownerIdentifier;
    private OwnerPIN pin;
    private boolean hasUserInitialized = false;

    // 암호화 관련 객체 (RAM)
    private final KeyPair myECKey;
    private final KeyAgreement ecdh;
    private final Cipher myAES;
    private final AESKey myAESKey;
    private final RandomData trng;

    // 디버깅용 전역 임시 배열 (공유 비밀 저장용)
    private byte[] sharedSecret;
    // ECDH 및 암호화 처리를 위한 임시 버퍼
    private byte[] tempBuffer;
    // 가독성 향상을 위한 전용 임시 배열 (RAM)
    private byte[] hostPublicKey;
    private byte[] challenge;

    private OneCardApplet(byte[] bArray, short bOffset, byte bLength) {
        byte ownerIdLength = bArray[bOffset];
        if (ownerIdLength >= 1 && ownerIdLength <= OWNER_DETAILS_MAX) {
            ownerIdentifier = new byte[ownerIdLength];
            Util.arrayCopy(
                    bArray,
                    (short) (bOffset + 1),
                    ownerIdentifier,
                    (short) 0,
                    ownerIdLength
            );
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        myECKey = ECP256.newKeyPair(false);
        myECKey.genKeyPair();
        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        ecdh.init(myECKey.getPrivate());
        myAES = Cipher.getInstance(Cipher.ALG_AES_ECB_PKCS5, false);
        myAESKey = (AESKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_AES_128,
                false
        );
        trng = RandomData.getInstance(RandomData.ALG_TRNG);
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        hasUserInitialized = false;

        sharedSecret = JCSystem.makeTransientByteArray(
                SHARED_SECRET_LENGTH,
                JCSystem.CLEAR_ON_DESELECT
        );
        tempBuffer = JCSystem.makeTransientByteArray(
                (short) 100,
                JCSystem.CLEAR_ON_DESELECT
        );
        hostPublicKey = JCSystem.makeTransientByteArray(
                HOST_PUBKEY_LENGTH,
                JCSystem.CLEAR_ON_DESELECT
        );
        challenge = JCSystem.makeTransientByteArray(
                CHALLENGE_LENGTH,
                JCSystem.CLEAR_ON_DESELECT
        );
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // AID, Info, Applet Data 파싱
        byte aidLen = bArray[bOffset];
        bOffset = (short) (bOffset + aidLen + 1);
        byte infoLen = bArray[bOffset];
        bOffset = (short) (bOffset + infoLen + 1);
        byte dataLen = bArray[bOffset];

        if (dataLen < 1 || dataLen - 1 > OWNER_DETAILS_MAX) ISOException.throwIt(
                ISO7816.SW_WRONG_LENGTH
        );

        new OneCardApplet(bArray, (short) (bOffset + 1), dataLen).register();
    }

    public boolean select() {
        return true;
    }

    private void initializePin(APDU apdu) {
        final byte[] buffer = apdu.getBuffer();
        final byte newPinLength = buffer[ISO7816.OFFSET_CDATA + OFFSET_LV_LENGTH];
        if (
                newPinLength < MIN_PIN_SIZE || newPinLength > MAX_PIN_SIZE
        ) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        pin.update(
                buffer,
                (short) (ISO7816.OFFSET_CDATA + OFFSET_LV_VALUE),
                newPinLength
        );
        pin.resetAndUnblock();
        hasUserInitialized = true;
    }

    private void changePin(APDU apdu) {
        final byte[] buffer = apdu.getBuffer();
        final byte oldPinLength = buffer[ISO7816.OFFSET_CDATA + OFFSET_LV_LENGTH];
        final short oldPinValueOffset = (short) (ISO7816.OFFSET_CDATA +
                OFFSET_LV_VALUE);
        final short newPinLvOffset = (short) (oldPinValueOffset + oldPinLength);
        final byte newPinLength = buffer[(byte) (newPinLvOffset +
                OFFSET_LV_LENGTH)];
        final short newPinValueOffset = (short) (newPinLvOffset + OFFSET_LV_VALUE);

        if (
                newPinLength < MIN_PIN_SIZE || newPinLength > MAX_PIN_SIZE
        ) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (
                !pin.check(buffer, oldPinValueOffset, oldPinLength)
        ) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        pin.update(buffer, newPinValueOffset, newPinLength);
        pin.resetAndUnblock();
    }

    private void getCardInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte ownerIdLength = (byte) ownerIdentifier.length;
        short totalLen = (short) (OFFSET_VALUE + ownerIdLength + 3);
        short pos = 0;
        buffer[pos++] = TAG_OWNER_ID;
        buffer[pos++] = ownerIdLength;
        Util.arrayCopy(ownerIdentifier, (short) 0, buffer, pos, ownerIdLength);
        pos += ownerIdLength;
        buffer[pos++] = TAG_PIN_STATUS;
        buffer[pos++] = (byte) 0x01;
        buffer[pos] = pin.getTriesRemaining();
        apdu.setOutgoingAndSend((short) 0, totalLen);
    }

    private void getECDHPublicKey(APDU apdu) {
        ECPublicKey epubk = (ECPublicKey) myECKey.getPublic();
        short len = epubk.getW(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void doExternalAuth(APDU apdu) {
        final byte[] buffer = apdu.getBuffer();
        final short incomingLength = buffer[ISO7816.OFFSET_LC];
        boolean isPinPassed = false;

        // 입력 데이터 길이 검증
        if (incomingLength == MIN_APDU_LEN_NO_PIN) {
            // PIN 미사용 (81바이트: 65바이트 공개키 + 16바이트 챌린지)
        } else if (
                incomingLength >= MIN_APDU_LEN_WITH_PIN &&
                        incomingLength <= MAX_APDU_LEN_WITH_PIN
        ) {
            final short pinTlvOffset = (short) (ISO7816.OFFSET_CDATA +
                    HOST_PUBKEY_LENGTH +
                    CHALLENGE_LENGTH);
            if (
                    buffer[pinTlvOffset + OFFSET_TAG] != TAG_PIN_STATUS
            ) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            byte pinLength = buffer[pinTlvOffset + OFFSET_LENGTH];
            if (
                    !pin.check(buffer, (short) (pinTlvOffset + OFFSET_VALUE), pinLength)
            ) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            isPinPassed = true;
            pin.reset();
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // 1. APDU 버퍼에서 데이터를 명확한 이름의 변수로 복사
        final short hostPubKeyOffset = ISO7816.OFFSET_CDATA;
        final short challengeOffset = (short) (ISO7816.OFFSET_CDATA + HOST_PUBKEY_LENGTH);

        Util.arrayCopy(buffer, hostPubKeyOffset, hostPublicKey, (short) 0, HOST_PUBKEY_LENGTH);
        Util.arrayCopy(buffer, challengeOffset, challenge, (short) 0, CHALLENGE_LENGTH);

        // ECDH 공유 비밀 계산
        try {
            // 호스트 공개키 검증 (uncompressed point 확인)
            if (hostPublicKey[0] != (byte) 0x04) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            // ECDH 공유 비밀 생성 시, APDU 버퍼 대신 전용 변수 사용
            short secretLength = ecdh.generateSecret(
                    hostPublicKey,
                    (short) 0,
                    HOST_PUBKEY_LENGTH,
                    sharedSecret,
                    (short) 0
            );

            if (secretLength < 16) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // AES 키 설정 (공유 비밀의 첫 16바이트 사용)
        try {
            myAESKey.setKey(sharedSecret, (short) 0);
            myAES.init(myAESKey, Cipher.MODE_ENCRYPT);
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // 챌린지의 처음 4바이트를 난수로 교체
        trng.nextBytes(challenge, (short) 0, (short) 4);

        // 암호화할 데이터를 tempBuffer에 준비
        short plaintextLength;
        try {
            if (isPinPassed) {
                plaintextLength = 32;
                // 챌린지 복사
                Util.arrayCopy(challenge, (short) 0, tempBuffer, (short) 0, CHALLENGE_LENGTH);
                // PIN 통과 플래그 복사
                Util.arrayCopy(PIN_PASSED_FLAG, (short) 0, tempBuffer, CHALLENGE_LENGTH, (short) PIN_PASSED_FLAG.length);
                // 패딩
                Util.arrayFillNonAtomic(tempBuffer, (short) (CHALLENGE_LENGTH + PIN_PASSED_FLAG.length), (short) 13, (byte) 0x00);
            } else {
                plaintextLength = 16;
                // 챌린지 복사
                Util.arrayCopy(challenge, (short) 0, tempBuffer, (short) 0, CHALLENGE_LENGTH);
            }

            short len = myAES.doFinal(
                    tempBuffer,
                    (short) 0,
                    plaintextLength,
                    buffer,
                    (short) 0
            );
            apdu.setOutgoingAndSend((short) 0, len);

        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != CLA_ONECARD_COMMON)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        // PIN 시도 횟수가 소진되면 보안을 위해 인증 요청에 대한 처리를 거부함
        if (pin.getTriesRemaining() == 0) {
            if (buf[ISO7816.OFFSET_INS] == INS_GET_CARD_INFO)
                getCardInfo(apdu);
            else
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return;
        }

        byte ins = buf[ISO7816.OFFSET_INS];
        if (hasUserInitialized) {
            // PIN 초기화가 완료된 경우 모든 기능을 실행할 수 있음
            switch (ins) {
                case INS_CHANGE_OWNERPIN:
                    changePin(apdu);
                    break;
                case INS_GET_PUBLIC_KEY:
                    getECDHPublicKey(apdu);
                    break;
                case INS_GET_CARD_INFO:
                    getCardInfo(apdu);
                    break;
                case INS_EXT_AUTHENTICATE:
                    doExternalAuth(apdu);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else {
            // PIN을 초기화하지 않은 경우 실행할 수 있는 기능
            switch (ins) {
                case INS_INIT_OWNERPIN:
                    initializePin(apdu);
                    break;
                case INS_GET_PUBLIC_KEY:
                    getECDHPublicKey(apdu);
                    break;
                case INS_GET_CARD_INFO:
                    getCardInfo(apdu);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
    }
}