## OneCard Applet
<img src="./images/onecard.png" width="150" />
OneCard Applet은 온·오프라인 환경에서 사용 가능한 ID 카드를 구현하고자 개발된 오픈소스 자바 카드 애플릿입니다.<br><br>

이 레포지터리는 [OneCard 프로젝트](https://github.com/OneCard-OSS)의 일부입니다.

## 개요
관리자는 OneCard 애플릿을 [관리자 클라이언트](https://github.com/OneCard-OSS/OneCard-Admin-GUI)를 사용하여 호환되는 자바 카드에 발급한 뒤 ID 카드 내부에서 생성되는 ECDH 공개키를 DB에 등록한 뒤 조직 구성원에게 배포할 수 있으며,

조직 구성원은 관리자의 접근 허용 범위에 따라 조직 내 온라인 서비스(OAuth 2.0) 또는 IoT 장치(출입문, PC 등)에 접근할 수 있습니다.

또한 관리자는 고강도 인증을 사용하도록 지정한 일부 온라인 서비스에 한하여 OneCard로 로그인할 때 사용자에게 ID 카드 PIN을 요구할 수 있습니다.

## 주요 기능
* P256 ECDH 키 교환 알고리즘으로 유도된 AES-128 키를 사용한 시도-응답 인증을 수행하여 높은 수준의 보안성 제공
* 발급된 ID카드에 PIN 기능을 제공하여 카드의 도난에 따른 피해 최소화
* 구성원은 OneCard 앱을 사용하여 온라인 서비스에서 ID 카드로 인증 가능
* PIN은 구성원이 처음 ID 카드를 발급받은 후 OneCard 앱을 통해 초기 PIN 설정 또는 변경 가능
* PIN 무차별 대입 공격에 대비하기 위해 지정한 PIN 연속 시도 횟수(기본 6회)를 소진하면 스마트카드가 스스로 모든 인증 요청을 거부하며, 관리자에 의한 애플릿 재설치 전까지 ID 카드 사용 불가

## Test Tool
<img src="./images/demo.png" width="512" />

OneCard 애플릿을 수정한 후 본 레포지터리의 [test-tool](https://github.com/OneCard-OSS/OneCard-ID-Card/tree/main/test-gui)을 활용하면 애플릿이 올바르게 인증 절차를 수행하는지 쉽게 시험해볼 수 있습니다.
