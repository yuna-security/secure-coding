# 공식 체크리스트 ①~㉗ 전수 점검 (P9)

> 기준 문서: [`SYSTEM_DESIGN.ko.md`](SYSTEM_DESIGN.ko.md) §11 매핑표.
> 방법: 각 항목을 **구현 위치 → 검증 방법 → 자동화 테스트/증적 → 결과**로 연결한다.
> 자동화 테스트는 `pytest` **250 passed** 기준(2026-07-24). 기능별 상세 테스트(`test_p2~p8`)에
> 더해, 교차 관심사·침투 관점을 `tests/test_p9_checklist.py`(30건)로 통합 재검증했다.
> 범례: ✅ 자동화 테스트 통과 · 🟡 구현·설정 완료, 운영 증적은 P10(HTTPS/WSS·배포)에서 수집.

---

## 1. 요약

| 구분 | 항목 | 결과 |
|------|------|------|
| 자동화 테스트로 통과 | ①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑱⑲⑳㉑㉒㉔㉖㉗ (24) | ✅ |
| 구현·설정 완료, 운영 증적 P10 이월 | ⑰(WSS) ㉕(HTTPS) ㉓(OS 파일 권한 — POSIX 배포) (3) | 🟡 |

- 총 27개 항목 모두 구현·설계에 반영. 24개는 실행되는 테스트로 증명, 3개는 운영 배포(P10)에서 최종 증적 수집.
- 의존성(㉗)은 `requirements.txt` 전 항목 버전 고정을 테스트로 확인했다. `pip-audit 2.10.1`로 요구사항과 전이 의존성을 검사해 **"No known vulnerabilities found"**를 확인했다. 전체 가상환경 감사에서는 `pip 25.2`의 알려진 취약점 6건을 발견해 `pip 26.1.2`로 올렸고 재검사 결과도 취약점 0건이다. 원문 증적은 [`evidence/P9_DEPENDENCY_AUDIT.txt`](evidence/P9_DEPENDENCY_AUDIT.txt)에 남겼다.

---

## 2. 항목별 전수 점검

| # | 항목 | 구현 위치 | 검증 방법 | 테스트/증적 | 결과 |
|---|------|-----------|-----------|-------------|------|
| ① | 서버측 입력 검증 | `auth/product/report/wallet` service validators | 사용자명·비밀번호·가격 경계 및 악성 입력 거부 | `tests/test_p9_checklist.py::test_registration_validates_username_and_password_boundaries`, `tests/test_p9_checklist.py::test_price_validation_rejected`, `tests/test_p4_product.py::test_search_escapes_sql_wildcards_and_rejects_overlong_query` | ✅ |
| ② | CSRF 보호 | app factory `CSRFProtect` + 전 폼 토큰 | 토큰 누락 POST 거부 | `tests/test_p2_foundation.py::test_csrf_missing_token_rejected`, `tests/test_p4_product.py::test_new_requires_csrf`, `tests/test_p3_profile.py::test_me_post_requires_csrf`, 신고·관리자·송금 CSRF 테스트 | ✅ |
| ③ | 비밀번호 해시 | `auth/service.py` Argon2id | DB에 해시만(평문X) | `tests/test_p2_foundation.py::test_password_is_hashed_not_plaintext` | ✅ |
| ④ | 세션 쿠키 설정 | `config.py`(HttpOnly/SameSite/Secure) | Set-Cookie 플래그 | `tests/test_p9_checklist.py::test_session_cookie_flags`, `tests/test_p2_foundation.py::test_login_cookie_is_permanent_and_hardened`, `tests/test_p2_foundation.py::test_production_https_headers_and_secure_cookie` | ✅ |
| ⑤ | 세션 만료·재인증 | `config` lifetime + 비번변경 재인증 | 실제 만료 쿠키 접근 거부·현재비번 재확인 | `tests/test_p9_checklist.py::test_session_lifetime_and_expired_session_is_rejected`, `tests/test_p9_checklist.py::test_password_change_requires_current_password`, `tests/test_p2_foundation.py::test_dormant_user_existing_session_is_invalidated` | ✅ |
| ⑥ | 실패 로그인 방어 | `auth/service.py` 계정잠금 + `routes` IP limit | 5회 실패 잠금 | `tests/test_p2_foundation.py::test_login_lockout_after_failures` | ✅ |
| ⑦ | 오류 메시지 | `security.py` 전역 에러 핸들러 + 정제 로깅 | 스택트레이스 미노출 | `tests/test_p2_foundation.py::test_internal_error_is_generic_and_debugger_is_disabled`, `tests/test_p9_checklist.py::test_error_pages_leak_no_internals` | ✅ |
| ⑧ | 폼 입력 검증(가격) | `product/service.py::parse_price` | 음수·문자·범위초과 거부 | `tests/test_p9_checklist.py::test_price_validation_rejected` | ✅ |
| ⑨ | XSS 방어 | Jinja 자동 이스케이프 + 소켓 `textContent` | 스크립트 페이로드 무해화·채팅 HTML 해석 금지 | `tests/test_p9_checklist.py::test_stored_xss_in_bio_is_escaped`, `tests/test_p9_checklist.py::test_stored_xss_in_product_is_escaped`, `tests/test_p9_checklist.py::test_chat_client_uses_text_content_for_untrusted_messages` | ✅ |
| ⑩ | 인증된 사용자만 등록 | `product/routes.py` `@login_required` | 비로그인 등록 차단 | `tests/test_p4_product.py::test_new_requires_login`, `tests/test_p9_checklist.py::test_login_required_routes_reject_anonymous` | ✅ |
| ⑪ | 소유자 확인 | `product/service.py` 소유자 검사 | 타인 상품 수정·삭제 거부(IDOR) | `tests/test_p9_checklist.py::test_idor_cannot_edit_others_product`, `tests/test_p4_product.py::test_edit_owner_success_and_nonowner_forbidden` | ✅ |
| ⑫ | 데이터 무결성 | 전 모델 CHECK/UNIQUE + 원장 트리거 | 잘못된 형식 저장 거부 | `tests/test_p9_checklist.py::test_db_check_constraints_reject_bad_data`, `tests/test_p7_wallet.py::test_database_enforces_ledger_guardrails` | ✅ |
| ⑬ | 메시지 내용 검증 | `chat/service.py::validate_content` + DB CHECK + 클라이언트 `textContent` | 500자 초과·빈 메시지 거부·HTML 해석 금지 | `tests/test_p5_chat.py::test_global_empty_message_rejected`, `tests/test_p5_chat.py::test_global_too_long_message_rejected`, `tests/test_p9_checklist.py::test_chat_client_uses_text_content_for_untrusted_messages` | ✅ |
| ⑭ | 사용자 인증(Socket) | `chat/events.py` connect 세션 인증 | 미인증·휴면 연결 차단 | `tests/test_p5_chat.py::test_socket_rejects_unauthenticated`, `tests/test_p5_chat.py::test_socket_rejects_dormant_after_login` | ✅ |
| ⑮ | 메시지 검증(서버측) | `chat/events.py` 발신자=세션, `_field` 방어 | 위조 필드 무시 | `tests/test_p5_chat.py::test_global_sender_is_server_session_not_client`, `tests/test_p5_chat.py::test_global_non_object_payload_rejected_without_server_error` | ✅ |
| ⑯ | Rate Limiting | 채팅 사용자 ID 카운터(HTTP 로그인·신고·송금은 Flask-Limiter 보조 통제) | 메시지·방 참가 플러딩 제한 | `tests/test_p5_chat.py::test_global_rate_limited`, `tests/test_p5_chat.py::test_join_dm_is_rate_limited_per_user` | ✅ |
| ⑰ | 연결 암호화(WSS) | 운영 HTTPS/WSS(ngrok/역방향 프록시) | wss:// 접속 확인 | 🟡 P10 배포 증적(설정 준비 완료: `SOCKET_ALLOWED_ORIGINS` 동일 출처) | 🟡 |
| ⑱ | 신고 폼 입력 검증 | `report/service.py::validate_reason` + 대상 조회 | 미존재·비공개 대상 및 빈/과길이 사유 거부 | `tests/test_p6_report.py::test_report_hidden_or_unknown_product_404`, `tests/test_p6_report.py::test_report_reason_required_and_maxlength` | ✅ |
| ⑲ | 인증된 사용자 접근(신고) | `report/routes` `@login_required` | 비로그인 신고 차단 | `tests/test_p6_report.py::test_report_requires_login` | ✅ |
| ⑳ | 데이터 무결성·로그(신고) | `report/service` + `audit_log` + 검토 상태 | 접수·조치 감사 기록 | `tests/test_p6_report.py::test_report_product_success`, `tests/test_p8_admin.py::test_report_review_pending` | ✅ |
| ㉑ | 신고 남용 방지 | UNIQUE + service(자기/중복/활성집계/임계치) | 자기·중복 신고 거부, 활성만 집계 | `tests/test_p6_report.py::test_self_report_product_rejected`, `tests/test_p6_report.py::test_duplicate_product_report_rejected`, `tests/test_p6_report.py::test_dormant_reporters_not_counted` | ✅ |
| ㉒ | ORM·파라미터 바인딩 | 전 쿼리 ORM + 정렬 허용목록 | 정렬 주입을 기본 정렬로 강제, SQL 조건문 페이로드가 전체 조회를 만들지 않음 | `tests/test_p9_checklist.py::test_sort_field_injection_is_neutralized`, `tests/test_p9_checklist.py::test_search_sql_metacharacters_are_safe`, `tests/test_p4_product.py::test_search_escapes_sql_wildcards_and_rejects_overlong_query` | ✅ |
| ㉓ | DB 최소 권한 | `security.py` SQLite DB `0600` + app factory instance/uploads `0700` + 업로드 파일 `0600` | POSIX chmod 호출 자동화 검증·배포 권한 확인 | `tests/test_p9_checklist.py::test_posix_private_modes_are_applied_to_sqlite_and_instance`; 실제 POSIX/Windows ACL 증적은 P10 | 🟡 |
| ㉔ | 보안 헤더 | `security.py` after_request | CSP/XFO/XCTO/Referrer/Permissions 존재 | `tests/test_p9_checklist.py::test_security_headers_present`, `tests/test_p2_foundation.py::test_security_headers` | ✅ |
| ㉕ | HTTPS 적용 | 운영 HTTPS(ngrok/프록시) + prod Secure·HSTS | https 접속·HSTS 확인 | 🟡 P10 배포 증적(prod `SESSION_COOKIE_SECURE=True`, HSTS 헤더 준비 완료) | 🟡 |
| ㉖ | 에러·예외 처리 | 전역 핸들러(400/403/404/409/413/429/500) + 로그 마스킹 | 민감정보 없는 오류·로그 | `tests/test_p9_checklist.py::test_error_pages_leak_no_internals`, `tests/test_p2_foundation.py::test_internal_error_is_generic_and_debugger_is_disabled` | ✅ |
| ㉗ | 의존성 관리 | `requirements.txt` 버전 고정 | 전 항목 == 고정 + 요구사항/전체 환경 pip-audit | `tests/test_p9_checklist.py::test_requirements_are_pinned` + [`P9_DEPENDENCY_AUDIT.txt`](evidence/P9_DEPENDENCY_AUDIT.txt) → 요구사항 0건, pip 6건 조치 후 전체 환경 0건 | ✅ |

---

## 3. 침투 테스트(요약)

`tests/test_p9_checklist.py`에 통합한 침투 관점 결과:

- **인증·권한 우회(SR-02)**: 관리자 라우트 6종(GET)·상태변경(POST)에 대해 익명→로그인 리다이렉트, 일반 사용자→403. 지갑·채팅은 익명 차단. (`test_admin_routes_reject_anonymous_and_normal`, `test_admin_post_forbidden_for_normal_user`, `test_login_required_routes_reject_anonymous`)
- **IDOR**: 타인 상품 수정·삭제 403(`test_idor_cannot_edit_others_product`), 타인 지갑 내역 비노출(`test_p7::test_wallet_page_shows_only_own_history`), 비참여자 DM 차단(`test_p5` 3종).
- **주입(SQLi)**: 정렬 주입값을 `newest`로 정규화하고, `' OR '1'='1` 검색이 전체 상품을 노출하지 않음을 확인(`test_sort_field_injection_is_neutralized`, `test_search_sql_metacharacters_are_safe`).
- **저장형 XSS**: 소개글·상품에 스크립트 페이로드 저장 후 이스케이프 렌더링 확인.
- **원장 위·변조**: transfer UPDATE/DELETE를 DB 트리거로 차단(`test_p7::test_database_enforces_ledger_guardrails`).
- **경합**: 신고 판정·송금·지급의 동일 대상/동일 키 병렬 처리에서 정확히 1회 반영(`test_p8`/`test_p7` 병렬 테스트).

---

## 4. 운영 이월 항목(P10에서 증적 수집)

| 항목 | 현재 상태(준비 완료) | P10 수집 증적 |
|------|----------------------|----------------|
| ⑰ WSS | Socket.IO 동일 출처 정책, 세션 인증 | ngrok/프록시 wss:// 접속 캡처 |
| ㉕ HTTPS | prod `SESSION_COOKIE_SECURE=True`, HSTS 헤더 | https 접속·HSTS 응답 캡처 |
| ㉓ DB·업로드 권한 | SQLite DB `0600`, instance/uploads `0700`, 업로드 파일 `0600` 적용 코드·단위 검증 완료 | POSIX `stat` 및 Windows ACL 캡처 |

---

## 5. 결론

27개 항목 전부 구현·설계에 반영되었으며, 24개 항목은 자동화 테스트로 상시 회귀 검증된다(㉗은 버전 고정 테스트 + pip-audit 스캔 완료). 나머지 3개(⑰ WSS·㉕ HTTPS·㉓ OS 파일 권한)는 실제 배포(HTTPS/WSS, POSIX 파일시스템)가 필요한 운영 증적으로 P10에서 최종 수집한다. 본 문서는 최종 보고서(P11)의 체크리스트 근거로 그대로 사용한다.
