import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import binascii
from typing import Optional, Tuple, List

# 모듈 설치 여부 확인
try:
    from smartcard.System import readers
    from smartcard.CardConnection import CardConnection
    from smartcard.util import toHexString, toBytes
except ImportError:
    print("Needs the module 'pyscard' to run this application.")
    exit()

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import os
except ImportError:
    print("Needs the module 'cryptography' to run this application.")
    exit()

CLA_ONECARD = 0xFF
INS_GET_CARD_INFO = 0xA0
INS_GET_PUBLIC_KEY = 0xA1
INS_EXT_AUTHENTICATE = 0xA3
INS_INIT_OWNERPIN = 0x10
INS_CHANGE_OWNERPIN = 0x11
TAG_OWNER_ID = 0x49
TAG_PIN_STATUS = 0x50
DEFAULT_AID = "4F 6E 65 43 61 72 64"  # "OneCard"

class SmartCardApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("OneCardApplet Tester")
        self.geometry("1000x900")
        self.resizable(True, True)

        self.card_connection: Optional[CardConnection] = None
        self.card_public_key: Optional[bytes] = None
        self.readers: List = []
        
        self._create_widgets()
        self._setup_styles()

    def _setup_styles(self):
        """GUI 스타일 설정"""
        style = ttk.Style()
        style.configure('Success.TButton', foreground='green')
        style.configure('Warning.TButton', foreground='orange')
        style.configure('Error.TButton', foreground='red')

    def _create_widgets(self):
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        self._create_connection_section(main_frame)
        
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        left_panel = ttk.Frame(content_frame, width=350)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False) 

        self._create_applet_section(left_panel)
        
        self._create_functions_section(left_panel)

        self._create_log_section(content_frame)

    def _create_connection_section(self, parent):
        """리더기 연결 섹션 생성"""
        connection_frame = ttk.LabelFrame(parent, text="1. 스마트카드 리더기 연결", padding="10")
        connection_frame.pack(fill=tk.X, pady=5)
        
        # 리더기 선택
        reader_row = ttk.Frame(connection_frame)
        reader_row.pack(fill=tk.X, pady=2)
        
        ttk.Label(reader_row, text="리더기:").pack(side=tk.LEFT, padx=(0, 5))
        self.reader_combobox = ttk.Combobox(reader_row, state="readonly", width=50)
        self.reader_combobox.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # 버튼들
        button_row = ttk.Frame(connection_frame)
        button_row.pack(fill=tk.X, pady=(5, 0))
        
        self.refresh_button = ttk.Button(button_row, text="새로고침", command=self.update_reader_list, width=12)
        self.refresh_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.connect_button = ttk.Button(button_row, text="카드 연결", command=self.connect_card, width=12)
        self.connect_button.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_button = ttk.Button(button_row, text="연결 해제", state=tk.DISABLED, command=self.disconnect_card, width=12)
        self.disconnect_button.pack(side=tk.LEFT, padx=(5, 0))

        # 상태 표시
        self.connection_status = ttk.Label(connection_frame, text="연결 상태: 미연결", foreground="red")
        self.connection_status.pack(pady=(5, 0))

        # 초기 리더기 목록 업데이트
        self.update_reader_list()

    def _create_applet_section(self, parent):
        """애플릿 선택 섹션 생성"""
        applet_frame = ttk.LabelFrame(parent, text="2. 애플릿 선택", padding="10")
        applet_frame.pack(fill=tk.X, pady=(0, 10))
        
        aid_row = ttk.Frame(applet_frame)
        aid_row.pack(fill=tk.X, pady=2)
        
        ttk.Label(aid_row, text="AID:", width=8).pack(side=tk.LEFT)
        self.aid_entry = ttk.Entry(aid_row)
        self.aid_entry.insert(0, DEFAULT_AID)
        self.aid_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 5))
        
        self.select_applet_button = ttk.Button(aid_row, text="선택", command=self.select_applet, state=tk.DISABLED, width=8)
        self.select_applet_button.pack(side=tk.LEFT)

        # 애플릿 상태 표시
        self.applet_status = ttk.Label(applet_frame, text="애플릿 상태: 미선택", foreground="red")
        self.applet_status.pack(pady=(5, 0))

    def _create_functions_section(self, parent):
        """기능 테스트 섹션 생성"""
        functions_frame = ttk.LabelFrame(parent, text="3. 기능 테스트", padding="10")
        functions_frame.pack(fill=tk.BOTH, expand=True)
        
        # 기본 정보 조회 버튼들
        info_frame = ttk.Frame(functions_frame)
        info_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.get_info_button = ttk.Button(info_frame, text="카드 정보 조회 (A0)", 
                                          command=self.get_card_info, state=tk.DISABLED)
        self.get_info_button.pack(fill=tk.X, pady=2)
        
        self.get_pubkey_button = ttk.Button(info_frame, text="공개키 조회 (A1)", 
                                            command=self.get_public_key, state=tk.DISABLED)
        self.get_pubkey_button.pack(fill=tk.X, pady=2)

        # 공개키 표시 영역
        pubkey_label = ttk.Label(info_frame, text="공개키 (편집 가능):")
        pubkey_label.pack(anchor=tk.W, pady=(5, 2))
        
        self.pubkey_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, height=4, 
                                                     font=("Consolas", 9), state=tk.DISABLED)
        self.pubkey_text.pack(fill=tk.X, pady=(0, 5))

        
        # PIN 관리 섹션
        self._create_pin_section(functions_frame)
        
        # 인증 테스트 섹션
        self._create_auth_section(functions_frame)

    def _create_pin_section(self, parent):
        """PIN 관리 섹션 생성"""
        pin_frame = ttk.LabelFrame(parent, text="PIN 관리", padding="10")
        pin_frame.pack(fill=tk.X, pady=(10, 5))
        
        # 초기 PIN 설정
        init_pin_frame = ttk.Frame(pin_frame)
        init_pin_frame.pack(fill=tk.X, pady=(0, 8))
        
        init_pin_label_frame = ttk.Frame(init_pin_frame)
        init_pin_label_frame.pack(fill=tk.X, pady=(0, 2))
        ttk.Label(init_pin_label_frame, text="초기 PIN 설정:").pack(anchor=tk.W)
        
        init_pin_input_frame = ttk.Frame(init_pin_frame)
        init_pin_input_frame.pack(fill=tk.X)
        
        self.init_pin_entry = ttk.Entry(init_pin_input_frame, show="*")
        self.init_pin_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.init_pin_button = ttk.Button(init_pin_input_frame, text="설정 (10)", 
                                          command=self.initialize_pin, state=tk.DISABLED, width=10)
        self.init_pin_button.pack(side=tk.RIGHT)

        # 구분선
        separator = ttk.Separator(pin_frame, orient='horizontal')
        separator.pack(fill=tk.X, pady=5)

        # PIN 변경
        change_pin_frame = ttk.Frame(pin_frame)
        change_pin_frame.pack(fill=tk.X, pady=(5, 0))
        
        change_pin_label_frame = ttk.Frame(change_pin_frame)
        change_pin_label_frame.pack(fill=tk.X, pady=(0, 2))
        ttk.Label(change_pin_label_frame, text="PIN 변경:").pack(anchor=tk.W)
        
        old_pin_row = ttk.Frame(change_pin_frame)
        old_pin_row.pack(fill=tk.X, pady=1)
        ttk.Label(old_pin_row, text="기존 PIN:", width=10).pack(side=tk.LEFT)
        self.old_pin_entry = ttk.Entry(old_pin_row, show="*")
        self.old_pin_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        
        new_pin_row = ttk.Frame(change_pin_frame)
        new_pin_row.pack(fill=tk.X, pady=1)
        ttk.Label(new_pin_row, text="새 PIN:", width=10).pack(side=tk.LEFT)
        self.new_pin_entry = ttk.Entry(new_pin_row, show="*")
        self.new_pin_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        
        self.change_pin_button = ttk.Button(change_pin_frame, text="PIN 변경 (11)", 
                                            command=self.change_pin, state=tk.DISABLED)
        self.change_pin_button.pack(fill=tk.X, pady=(5, 0))

    def _create_auth_section(self, parent):
        """인증 테스트 섹션 생성"""
        auth_frame = ttk.LabelFrame(parent, text="카드 인증 테스트 (A3)", padding="10")
        auth_frame.pack(fill=tk.X, pady=(5, 0))
        
        # PIN 사용 여부 체크박스
        self.use_pin_var = tk.BooleanVar(value=False)
        self.use_pin_check = ttk.Checkbutton(auth_frame, text="PIN 인증 사용", 
                                             variable=self.use_pin_var, command=self._on_pin_check_changed)
        self.use_pin_check.pack(anchor=tk.W, pady=(0, 5))
        
        # PIN 입력 필드
        pin_auth_frame = ttk.Frame(auth_frame)
        pin_auth_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(pin_auth_frame, text="인증용 PIN:", width=10).pack(side=tk.LEFT)
        self.auth_pin_entry = ttk.Entry(pin_auth_frame, show="*", state=tk.DISABLED)
        self.auth_pin_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        
        # 인증 실행 버튼
        self.auth_button = ttk.Button(auth_frame, text="[인증 실행]", 
                                      command=self.external_auth, state=tk.DISABLED)
        self.auth_button.pack(fill=tk.X, pady=(5, 0))

    def _create_log_section(self, parent):
        """로그 섹션 생성"""
        log_frame = ttk.LabelFrame(parent, text="실행 로그 및 디버그 정보", padding="10")
        log_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # 로그 제어 버튼들
        log_controls = ttk.Frame(log_frame)
        log_controls.pack(fill=tk.X, pady=(0, 5))
        
        self.clear_log_button = ttk.Button(log_controls, text="로그 비우기", command=self.clear_log)
        self.clear_log_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.save_log_button = ttk.Button(log_controls, text="로그 저장", command=self.save_log)
        self.save_log_button.pack(side=tk.LEFT)
        
        # 로그 텍스트 영역
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=70, height=35, 
                                                  font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 로그 텍스트 스타일 설정
        self.log_text.tag_configure("success", foreground="green")
        self.log_text.tag_configure("error", foreground="red")
        self.log_text.tag_configure("warning", foreground="orange")
        self.log_text.tag_configure("info", foreground="blue")
        self.log_text.tag_configure("debug", foreground="purple")

    def _on_pin_check_changed(self):
        """PIN 체크박스 상태 변경 이벤트"""
        if self.use_pin_var.get():
            self.auth_pin_entry.config(state=tk.NORMAL)
        else:
            self.auth_pin_entry.config(state=tk.DISABLED)

    def log(self, message: str, level: str = "info"):
        """로그 메시지 출력"""
        def log_task():
            timestamp = time.strftime('%H:%M:%S')
            log_entry = f"[{timestamp}] {message}\n"
            
            if level == "success":
                self.log_text.insert(tk.END, log_entry, "success")
            elif level == "error":
                self.log_text.insert(tk.END, log_entry, "error")
            elif level == "warning":
                self.log_text.insert(tk.END, log_entry, "warning")
            elif level == "debug":
                self.log_text.insert(tk.END, log_entry, "debug")
            else:
                self.log_text.insert(tk.END, log_entry, "info")
            
            self.log_text.see(tk.END)
        
        self.after(0, log_task)

    def clear_log(self):
        """로그 내용 삭제"""
        self.log_text.delete('1.0', tk.END)
        self.log("로그가 초기화되었습니다.", "info")

    def save_log(self):
        """로그 내용을 파일로 저장"""
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="로그 저장"
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get('1.0', tk.END))
                self.log(f"로그가 저장되었습니다: {filename}", "success")
        except Exception as e:
            self.log(f"로그 저장 실패: {e}", "error")

    def update_reader_list(self):
        """리더기 목록 업데이트"""
        try:
            self.readers = readers()
            reader_names = [str(r) for r in self.readers] if self.readers else ["리더기가 없습니다"]
            self.reader_combobox['values'] = reader_names
            
            if self.readers:
                self.reader_combobox.current(0)
                self.log(f"{len(self.readers)}개의 리더기를 발견했습니다.", "success")
            else:
                self.log("리더기를 찾을 수 없습니다.", "warning")
                
        except Exception as e:
            self.log(f"리더기 목록 조회 실패: {e}", "error")

    def set_ui_state(self, state: str):
        """UI 상태 설정"""
        states = {
            'disconnected': {
                'connect_button': tk.NORMAL,
                'disconnect_button': tk.DISABLED,
                'select_applet_button': tk.DISABLED,
                'function_buttons': tk.DISABLED,
                'connection_status': ("연결 상태: 미연결", "red"),
                'applet_status': ("애플릿 상태: 미선택", "red")
            },
            'connected': {
                'connect_button': tk.DISABLED,
                'disconnect_button': tk.NORMAL,
                'select_applet_button': tk.NORMAL,
                'function_buttons': tk.DISABLED,
                'connection_status': ("연결 상태: 카드 연결됨", "green"),
                'applet_status': ("애플릿 상태: 미선택", "red")
            },
            'selected': {
                'connect_button': tk.DISABLED,
                'disconnect_button': tk.NORMAL,
                'select_applet_button': tk.NORMAL,
                'function_buttons': tk.NORMAL,
                'connection_status': ("연결 상태: 카드 연결됨", "green"),
                'applet_status': ("애플릿 상태: 선택됨", "green")
            }
        }
        
        if state not in states:
            return
            
        config = states[state]
        
        # 버튼 상태 설정
        self.connect_button.config(state=config['connect_button'])
        self.disconnect_button.config(state=config['disconnect_button'])
        self.select_applet_button.config(state=config['select_applet_button'])
        
        # 기능 버튼들 상태 설정
        function_buttons = [
            self.get_info_button, self.get_pubkey_button, self.init_pin_button,
            self.change_pin_button, self.auth_button
        ]
        for button in function_buttons:
            button.config(state=config['function_buttons'])
        
        # --- 변경점: 공개키 텍스트 박스 상태도 함께 관리 ---
        self.pubkey_text.config(state=config['function_buttons'])
        # --- 변경점 끝 ---

        # 상태 레이블 업데이트
        status_text, status_color = config['connection_status']
        self.connection_status.config(text=status_text, foreground=status_color)
        
        status_text, status_color = config['applet_status']
        self.applet_status.config(text=status_text, foreground=status_color)

    def connect_card(self):
        """스마트카드 연결"""
        if not self.reader_combobox.get() or self.reader_combobox.get() == "리더기가 없습니다":
            messagebox.showerror("오류", "유효한 리더기를 선택하세요.")
            return
            
        try:
            reader_index = self.reader_combobox.current()
            if reader_index < 0 or reader_index >= len(self.readers):
                messagebox.showerror("오류", "리더기 선택이 올바르지 않습니다.")
                return
                
            reader = self.readers[reader_index]
            self.card_connection = reader.createConnection()
            self.card_connection.connect()
            
            atr = self.card_connection.getATR()
            self.log(f"리더기 연결 성공: {reader}", "success")
            self.log(f"ATR: {toHexString(atr)}", "debug")
            
            self.set_ui_state('connected')
            
        except Exception as e:
            self.log(f"리더기 연결 실패: {e}", "error")
            messagebox.showerror("연결 오류", f"리더기 연결 실패:\n{e}")
            self.card_connection = None

    def disconnect_card(self):
        """스마트카드 연결 해제"""
        if self.card_connection:
            try:
                self.card_connection.disconnect()
                self.log("리더기 연결이 해제되었습니다.", "info")
            except Exception as e:
                self.log(f"연결 해제 중 오류: {e}", "warning")
            finally:
                self.card_connection = None
                self.card_public_key = None
                # --- 변경점: 연결 해제 시 공개키 텍스트 박스 초기화 ---
                self.pubkey_text.config(state=tk.NORMAL)
                self.pubkey_text.delete('1.0', tk.END)
                # --- 변경점 끝 ---
                self.set_ui_state('disconnected')

    def _transmit_apdu(self, apdu: List[int]) -> Optional[Tuple[List[int], int, int]]:
        """APDU 전송 및 응답 수신"""
        if not self.card_connection:
            self.log("오류: 카드가 연결되지 않았습니다.", "error")
            return None
            
        try:
            self.log(f"--> C-APDU: {toHexString(apdu)}", "debug")
            data, sw1, sw2 = self.card_connection.transmit(apdu)
            self.log(f"<-- R-APDU: {toHexString(data)} SW: {sw1:02X}{sw2:02X}", "debug")
            
            if (sw1, sw2) != (0x90, 0x00):
                error_msg = f"카드 오류 응답: SW={sw1:02X}{sw2:02X}"
                self.log(error_msg, "error")
                messagebox.showerror("APDU 오류", error_msg)
                return None
                
            return data, sw1, sw2
            
        except Exception as e:
            error_msg = f"APDU 전송 오류: {e}"
            self.log(error_msg, "error")
            messagebox.showerror("전송 오류", f"APDU 전송 중 오류 발생:\n{e}")
            return None

    def run_in_thread(self, target_func):
        """별도 스레드에서 함수 실행"""
        thread = threading.Thread(target=target_func, daemon=True)
        thread.start()

    def select_applet(self):
        """애플릿 선택"""
        self.run_in_thread(self._select_applet_task)

    def _select_applet_task(self):
        """애플릿 선택 작업"""
        aid_str = self.aid_entry.get().replace(" ", "")
        if not aid_str:
            self.after(0, lambda: messagebox.showerror("입력 오류", "AID를 입력하세요."))
            return
            
        try:
            aid_bytes = toBytes(aid_str)
        except Exception:
            self.after(0, lambda: messagebox.showerror("입력 오류", "AID 형식이 올바르지 않습니다. (예: 4F 6E 65 43 61 72 64)"))
            return
            
        apdu = [0x00, 0xA4, 0x04, 0x00, len(aid_bytes)] + aid_bytes
        
        if self._transmit_apdu(apdu):
            self.log("애플릿 선택 성공", "success")
            self.after(0, lambda: self.set_ui_state('selected'))
        else:
            self.log("애플릿 선택 실패", "error")

    def get_card_info(self):
        """카드 정보 조회"""
        self.run_in_thread(self._get_card_info_task)

    def _get_card_info_task(self):
        """카드 정보 조회 작업"""
        apdu = [CLA_ONECARD, INS_GET_CARD_INFO, 0x00, 0x00, 0x00]
        response = self._transmit_apdu(apdu)
        
        if not response:
            return
            
        try:
            data = response[0]
            pos = 0
            owner_id = "N/A"
            tries_remaining = "N/A"
            
            # 소유자 ID 파싱
            if pos < len(data) and data[pos] == TAG_OWNER_ID:
                pos += 1
                if pos < len(data):
                    length = data[pos]
                    pos += 1
                    if pos + length <= len(data):
                        owner_id = bytes(data[pos:pos + length]).decode('utf-8', 'ignore')
                        pos += length
            
            # PIN 상태 파싱
            if pos < len(data) and data[pos] == TAG_PIN_STATUS:
                pos += 1
                if pos < len(data):
                    length = data[pos]
                    pos += 1
                    if pos < len(data):
                        tries_remaining = data[pos]
            
            info_msg = f"소유자 식별자: {owner_id}\n남은 PIN 시도 횟수: {tries_remaining}"
            self.log(f"카드 정보 - {info_msg.replace(chr(10), ', ')}", "info")
            self.after(0, lambda: messagebox.showinfo("카드 정보", info_msg))
            
        except Exception as e:
            self.log(f"카드 정보 파싱 오류: {e}", "error")

    def get_public_key(self):
        """공개키 조회"""
        self.run_in_thread(self._get_public_key_task)

    def _get_public_key_task(self):
        """공개키 조회 작업"""
        apdu = [CLA_ONECARD, INS_GET_PUBLIC_KEY, 0x00, 0x00, 0x00]
        response = self._transmit_apdu(apdu)
        
        if not response:
            return
            
        self.card_public_key = bytes(response[0])
        pubkey_hex = hex(self.card_public_key)

        self.log(f"카드 공개키 수신 ({len(self.card_public_key)}B): {pubkey_hex}", "success")

        def update_pubkey_text():
            self.pubkey_text.config(state=tk.NORMAL)
            self.pubkey_text.delete('1.0', tk.END)
            self.pubkey_text.insert(tk.END, pubkey_hex)
        self.after(0, update_pubkey_text)
        
        # 공개키 유효성 검증
        try:
            if len(self.card_public_key) == 65 and self.card_public_key[0] == 0x04:
                # Python cryptography 라이브러리로 공개키 검증
                ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), self.card_public_key)
                self.log("✓ 카드 공개키 검증 성공 - 올바른 P-256 uncompressed point 형식", "success")
            else:
                self.log(f"⚠ 예상과 다른 공개키 형식 (길이: {len(self.card_public_key)}, 첫 바이트: 0x{self.card_public_key[0]:02X})", "warning")
        except Exception as e:
            self.log(f"✗ 카드 공개키 검증 실패: {e}", "error")
        
        self.after(0, lambda: messagebox.showinfo("공개키", f"카드의 공개키를 성공적으로 수신했습니다.\n길이: {len(self.card_public_key)} 바이트"))

    def initialize_pin(self):
        """초기 PIN 설정"""
        self.run_in_thread(self._initialize_pin_task)

    def _initialize_pin_task(self):
        """초기 PIN 설정 작업"""
        pin = self.init_pin_entry.get()
        if not pin:
            self.after(0, lambda: messagebox.showerror("입력 오류", "초기 PIN을 입력하세요."))
            return
            
        if len(pin) < 4 or len(pin) > 8:
            self.after(0, lambda: messagebox.showerror("입력 오류", "PIN은 4-8자리여야 합니다."))
            return
            
        pin_bytes = pin.encode('ascii')
        apdu = [CLA_ONECARD, INS_INIT_OWNERPIN, 0x00, 0x00, len(pin_bytes) + 1, len(pin_bytes)] + list(pin_bytes)
        
        if self._transmit_apdu(apdu):
            self.log("초기 PIN 설정 성공", "success")
            self.after(0, lambda: messagebox.showinfo("성공", "초기 PIN이 설정되었습니다."))
            self.after(0, lambda: self.init_pin_entry.delete(0, tk.END)) # 입력 필드 초기화

    def change_pin(self):
        """PIN 변경"""
        self.run_in_thread(self._change_pin_task)

    def _change_pin_task(self):
        """PIN 변경 작업"""
        old_pin = self.old_pin_entry.get()
        new_pin = self.new_pin_entry.get()
        
        if not old_pin or not new_pin:
            self.after(0, lambda: messagebox.showerror("입력 오류", "기존 PIN과 새 PIN을 모두 입력하세요."))
            return
            
        if len(new_pin) < 4 or len(new_pin) > 8:
            self.after(0, lambda: messagebox.showerror("입력 오류", "새 PIN은 4-8자리여야 합니다."))
            return
            
        old_pin_bytes = old_pin.encode('ascii')
        new_pin_bytes = new_pin.encode('ascii')
        
        data_field = [len(old_pin_bytes)] + list(old_pin_bytes) + [len(new_pin_bytes)] + list(new_pin_bytes)
        apdu = [CLA_ONECARD, INS_CHANGE_OWNERPIN, 0x00, 0x00, len(data_field)] + data_field
        
        if self._transmit_apdu(apdu):
            self.log("PIN 변경 성공", "success")
            self.after(0, lambda: messagebox.showinfo("성공", "PIN이 변경되었습니다."))
            # 입력 필드들 초기화
            def clear_entries():
                self.old_pin_entry.delete(0, tk.END)
                self.new_pin_entry.delete(0, tk.END)
            self.after(0, clear_entries)

    def external_auth(self):
        """외부 인증 실행"""
        self.run_in_thread(self._external_auth_task)

    def _external_auth_task(self):
        """외부 인증 작업"""
        pubkey_hex_from_ui = self.pubkey_text.get('1.0', tk.END).strip().replace(" ", "")
        if not pubkey_hex_from_ui:
            self.after(0, lambda: messagebox.showwarning("준비 필요", "공개키가 없습니다. '공개키 조회 (A1)'를 실행하거나 직접 입력하세요."))
            return
        
        try:
            card_public_key_bytes = bytes(toBytes(pubkey_hex_from_ui))
            self.log(f"인증에 사용할 공개키 (UI에서 읽음): {toHexString(list(card_public_key_bytes))}", "debug")
        except Exception as e:
            self.log(f"UI의 공개키 형식이 올바르지 않습니다: {e}", "error")
            self.after(0, lambda: messagebox.showerror("입력 오류", f"공개키 형식이 올바르지 않습니다.\n{e}"))
            return
            
        # PIN 사용 여부 확인
        use_pin = self.use_pin_var.get()
        auth_pin = ""
        
        if use_pin:
            auth_pin = self.auth_pin_entry.get()
            if not auth_pin:
                self.after(0, lambda: messagebox.showerror("입력 오류", "PIN 인증을 사용하려면 인증용 PIN을 입력하세요."))
                return
            if len(auth_pin) < 4 or len(auth_pin) > 8:
                self.after(0, lambda: messagebox.showerror("입력 오류", "PIN은 4-8자리여야 합니다."))
                return
        
        try:
            self.log("\n" + "="*50, "info")
            self.log("[카드 인증 프로세스 시작]", "info")
            self.log("="*50, "info")
            
            # 1. 호스트 키페어 생성
            self.log("1. 호스트 ECDH 키페어 생성", "info")
            host_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            host_public_key_bytes = host_private_key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint
            )
            
            private_value = host_private_key.private_numbers().private_value
            self.log(f"    * 호스트 개인키 (d): {private_value:064X}", "debug")
            self.log(f"    * 호스트 공개키 (Q): {toHexString(list(host_public_key_bytes))}", "debug")
            
            # 2. 랜덤 챌린지 생성
            self.log("2. 랜덤 챌린지 생성", "info")
            challenge = os.urandom(16)
            self.log(f"    * 챌린지 (16B): {toHexString(list(challenge))}", "debug")
            
            # 3. APDU 데이터 구성
            self.log("3. APDU 데이터 구성", "info")
            data_field = list(host_public_key_bytes) + list(challenge)
            
            if use_pin:
                pin_bytes = auth_pin.encode('ascii')
                pin_tlv = [TAG_PIN_STATUS, len(pin_bytes)] + list(pin_bytes)
                data_field += pin_tlv
                self.log(f"    * PIN TLV 추가: {toHexString(pin_tlv)}", "debug")
            
            self.log(f"    * 총 데이터 길이: {len(data_field)} 바이트", "debug")
            
            # 4. 카드에 인증 요청 전송
            self.log("4. 카드로 인증 요청 전송 중...", "info")
            apdu = [CLA_ONECARD, INS_EXT_AUTHENTICATE, 0x00, 0x00, len(data_field)] + data_field
            response = self._transmit_apdu(apdu)
            
            if not response:
                self.log("❌ 카드 인증 요청 실패", "error")
                return
                
            encrypted_response = response[0]
            self.log(f"    암호화된 응답 수신 ({len(encrypted_response)}B): {toHexString(encrypted_response)}", "success")
            
            # 5. 호스트에서 ECDH 공유 비밀 계산
            self.log("5. 호스트에서 ECDH 공유 비밀 계산 중...", "info")
            
            # 카드 공개키 객체 생성 (UI에서 읽어온 값 사용)
            card_public_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), card_public_key_bytes)
            
            # ECDH 교환 수행
            shared_secret = host_private_key.exchange(ec.ECDH(), card_public_key_obj)
            aes_key = shared_secret[:16]  # 첫 16바이트를 AES 키로 사용
            
            self.log(f"    * ECDH 공유 비밀 (Z): {toHexString(list(shared_secret))}", "debug")
            self.log(f"    * AES 세션키 (16B): {toHexString(list(aes_key))}", "debug")
            
            # 6. 카드 응답 복호화
            self.log("6. 카드 응답 복호화", "info")
            decryptor = Cipher(algorithms.AES(aes_key), modes.ECB(), default_backend()).decryptor()
            decrypted_data = decryptor.update(bytes(encrypted_response)) + decryptor.finalize()
            self.log(f"    * 복호화된 데이터 ({len(decrypted_data)}B): {toHexString(list(decrypted_data))}", "success")
            
            # 7. 챌린지-응답 검증
            self.log("7. 챌린지-응답 검증 중", "info")
            
            # 카드에서 처음 4바이트를 난수로 변경하므로, 뒤의 12바이트만 비교
            original_suffix = challenge[4:]
            decrypted_suffix = decrypted_data[4:16]
            
            self.log(f"    • 원본 챌린지 (뒷 12B):     {toHexString(list(original_suffix))}", "debug")
            self.log(f"    • 복호화된 챌린지 (뒷 12B): {toHexString(list(decrypted_suffix))}", "debug")
            
            if original_suffix != decrypted_suffix:
                self.log("    ❌ 챌린지 불일치 - 인증 실패!", "error")
                self.after(0, lambda: messagebox.showerror("인증 실패", "챌린지-응답 검증에 실패했습니다!"))
                return
                
            self.log("    ✅ 챌린지 일치 확인!", "success")
            
            # 8. PIN 인증 플래그 검증 (PIN 사용시)
            auth_result = "카드 인증 성공"
            
            if use_pin:
                self.log("8. PIN 인증 플래그 검증 중...", "info")
                
                if len(decrypted_data) >= 32:
                    expected_flag = [TAG_PIN_STATUS, 0x01, 0x01]
                    received_flag = list(decrypted_data[16:19])
                    
                    self.log(f"    • 기대 플래그: {toHexString(expected_flag)}", "debug")
                    self.log(f"    • 수신 플래그: {toHexString(received_flag)}", "debug")
                    
                    if received_flag == expected_flag:
                        self.log("    ✅ PIN 플래그 일치 확인!", "success")
                        auth_result += " (PIN 인증 포함)"
                    else:
                        self.log("    ❌ PIN 플래그 불일치 - 인증 실패!", "error")
                        self.after(0, lambda: messagebox.showerror("인증 실패", "PIN 인증 플래그 검증에 실패했습니다!"))
                        return
                else:
                    self.log("    ❌ 복호화된 데이터 길이 부족 - PIN 검증 불가!", "error")
                    self.after(0, lambda: messagebox.showerror("인증 실패", "PIN 사용 모드에서 응답 데이터 길이가 부족합니다!"))
                    return
            else:
                self.log("8. PIN 미사용 모드 - PIN 검증 생략", "info")
            
            # 9. 인증 완료
            self.log("9. 인증 프로세스 완료", "success")
            self.log("="*50, "info")
            self.log(f"성공: {auth_result}!", "success")
            self.log("="*50 + "\n", "info")
            
            self.after(0, lambda: messagebox.showinfo("인증 성공", f"{auth_result}!\n\n모든 검증 단계를 통과했습니다."))
            
        except ValueError as ve:
            self.log(f"❌ 데이터 검증 오류: {ve}", "error")
            self.after(0, lambda: messagebox.showerror("검증 오류", f"데이터 검증 중 오류 발생:\n{ve}"))
        except Exception as e:
            self.log(f"❌ 인증 프로세스 오류: {e}", "error")
            self.after(0, lambda: messagebox.showerror("인증 오류", f"인증 과정 중 예상치 못한 오류 발생:\n{e}"))

    def on_closing(self):
        """애플리케이션 종료 처리"""
        self.log("애플리케이션을 종료합니다...", "info")
        self.disconnect_card()
        self.destroy()

if __name__ == "__main__":
    app = SmartCardApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    app.log("OneCardApplet 테스트 GUI가 시작되었습니다.", "success")
    app.log("1) 리더기 연결 → 2) 카드 연결 → 3) 애플릿 선택 → 4) 초기 PIN 설정 → 5) 공개키 조회 → 6) 카드 인증 테스트", "info")

    app.mainloop()


