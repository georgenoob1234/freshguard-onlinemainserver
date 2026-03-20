"""Minimal i18n for OMS Admin UI — Russian (default) and English."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

router = APIRouter(prefix="/admin", tags=["admin-ui"])

LANG_COOKIE = "oms_admin_ui_lang"
DEFAULT_LANG = "ru"
SUPPORTED = {"ru", "en"}

# Translation catalog — keys with RU/EN variants
# Keys match the UI text needs across all templates
CATALOG: dict[str, dict[str, str]] = {
    # Navigation / shared
    "app_title": {"ru": "OMS Admin", "en": "OMS Admin"},
    "nav_dashboard": {"ru": "Обзор", "en": "Dashboard"},
    "nav_users": {"ru": "Пользователи", "en": "Users"},
    "nav_stores": {"ru": "Магазины", "en": "Stores"},
    "nav_devices": {"ru": "Устройства", "en": "Devices"},
    "nav_enroll_tokens": {"ru": "Токены регистрации", "en": "Enroll Tokens"},
    "logout": {"ru": "Выйти", "en": "Logout"},
    "switch_language": {"ru": "English", "en": "Русский"},
    "page_title_dashboard": {"ru": "Обзор", "en": "Dashboard"},
    "page_title_users": {"ru": "Пользователи", "en": "Users"},
    "page_title_user_detail": {"ru": "Пользователь {user_id}", "en": "User {user_id}"},
    "page_title_stores": {"ru": "Магазины", "en": "Stores"},
    "page_title_store_detail": {"ru": "Магазин {store_id}", "en": "Store {store_id}"},
    "page_title_devices": {"ru": "Устройства", "en": "Devices"},
    "page_title_device_detail": {"ru": "Устройство {device_id}", "en": "Device {device_id}"},
    "page_title_enroll_tokens": {"ru": "Токены регистрации", "en": "Enroll Tokens"},
    "page_title_login": {"ru": "Вход в панель управления", "en": "Admin Login"},
    # Flash messages
    "flash_confirm_required": {"ru": "Подтвердите действие.", "en": "Please confirm the action."},
    "flash_user_banned": {"ru": "Пользователь заблокирован.", "en": "User banned."},
    "flash_user_unbanned": {"ru": "Пользователь разблокирован.", "en": "User unbanned."},
    "flash_membership_updated": {"ru": "Членство обновлено.", "en": "Membership updated."},
    "flash_store_created": {"ru": "Магазин создан.", "en": "Store created."},
    "flash_store_updated": {"ru": "Магазин обновлен.", "en": "Store updated."},
    "flash_token_minted": {"ru": "Токен выпущен.", "en": "Token minted."},
    "flash_confirm_token_minting": {"ru": "Подтвердите выпуск токена.", "en": "Please confirm token minting."},
    # Errors
    "error_invalid_credentials": {"ru": "Неверное имя пользователя или пароль.", "en": "Invalid username or password."},
    "error_confirm_role_change": {"ru": "Подтвердите изменение роли.", "en": "Please confirm the role change."},
    "error_confirm_store_update": {"ru": "Подтвердите обновление магазина.", "en": "Please confirm store update."},
    "error_confirm_membership_change": {"ru": "Подтвердите изменение членства.", "en": "Please confirm membership change."},
    # Dashboard
    "stat_total_stores": {"ru": "Всего магазинов", "en": "Total Stores"},
    "stat_total_users": {"ru": "Всего пользователей", "en": "Total Users"},
    "stat_banned_users": {"ru": "Заблокировано", "en": "Banned Users"},
    "stat_total_memberships": {"ru": "Всего членств", "en": "Total Memberships"},
    "stat_total_devices": {"ru": "Всего устройств", "en": "Total Devices"},
    "stat_connected_devices": {"ru": "Подключенных", "en": "Connected Devices"},
    "stat_online_devices": {"ru": "Онлайн", "en": "Online Devices"},
    # Users list
    "search_placeholder": {"ru": "Поиск пользователей...", "en": "Search users..."},
    "filter_banned_only": {"ru": "Только заблокированные", "en": "Banned only"},
    "search_button": {"ru": "Найти", "en": "Search"},
    "table_user_id": {"ru": "ID", "en": "User ID"},
    "table_banned": {"ru": "Статус", "en": "Status"},
    "table_created": {"ru": "Создан", "en": "Created"},
    "table_actions": {"ru": "Действия", "en": "Actions"},
    "status_banned": {"ru": "Заблокирован", "en": "Banned"},
    "status_active": {"ru": "Активен", "en": "Active"},
    "action_view": {"ru": "Открыть", "en": "View"},
    "empty_no_users": {"ru": "Пользователи не найдены.", "en": "No users found."},
    "pagination_prev": {"ru": "← Назад", "en": "← Previous"},
    "pagination_next": {"ru": "Вперед →", "en": "Next →"},
    "page_of": {"ru": "Стр. {page} из {total}", "en": "Page {page} of {total}"},
    # User detail
    "section_identity": {"ru": "Личность", "en": "Identity"},
    "section_provider_identities": {"ru": "Идентификаторы провайдеров", "en": "Provider identities"},
    "section_ban_unban": {"ru": "Блокировка / Разблокировка", "en": "Ban / Unban"},
    "section_memberships": {"ru": "Членства", "en": "Memberships"},
    "label_banned": {"ru": "Статус блокировки:", "en": "Banned:"},
    "label_ban_reason": {"ru": "Причина:", "en": "Ban reason:"},
    "label_created": {"ru": "Создан:", "en": "Created:"},
    "label_last_seen": {"ru": "Последняя активность:", "en": "Last seen:"},
    "value_banned_yes": {"ru": "да", "en": "yes"},
    "value_banned_no": {"ru": "нет", "en": "no"},
    "value_none": {"ru": "—", "en": "-"},
    "table_provider": {"ru": "Провайдер", "en": "Provider"},
    "table_provider_user_id": {"ru": "ID провайдера", "en": "Provider User ID"},
    "table_provider_chat_id": {"ru": "Chat ID", "en": "Provider Chat ID"},
    "table_username": {"ru": "Имя пользователя", "en": "Username"},
    "table_display_name": {"ru": "Отображаемое имя", "en": "Display Name"},
    "empty_no_identities": {"ru": "Идентификаторы не найдены.", "en": "No identities found."},
    "form_set_banned_state": {"ru": "Установить статус блокировки", "en": "Set banned state"},
    "option_not_banned": {"ru": "Не заблокирован", "en": "Not banned"},
    "option_banned": {"ru": "Заблокирован", "en": "Banned"},
    "label_reason": {"ru": "Причина", "en": "Reason"},
    "confirm_ban_state_change": {"ru": "Подтвердить изменение статуса блокировки", "en": "Confirm ban state change"},
    "button_apply_ban_state": {"ru": "Применить статус", "en": "Apply ban state"},
    "table_store": {"ru": "Магазин", "en": "Store"},
    "table_role": {"ru": "Роль", "en": "Role"},
    "table_store_active": {"ru": "Магазин активен", "en": "Store active"},
    "value_yes": {"ru": "да", "en": "yes"},
    "value_no": {"ru": "нет", "en": "no"},
    "empty_no_memberships": {"ru": "Нет активных членств.", "en": "No active memberships."},
    "add_or_update_membership": {"ru": "Добавить или обновить членство", "en": "Add or update membership"},
    "label_store": {"ru": "Магазин", "en": "Store"},
    "select_store_placeholder": {"ru": "Выберите магазин...", "en": "Select store..."},
    "label_role": {"ru": "Роль", "en": "Role"},
    "checkbox_set_active_store": {"ru": "Сделать активным магазином", "en": "Set as active store"},
    "confirm_role_assignment": {"ru": "Подтвердить назначение/обновление роли", "en": "Confirm role assignment/update"},
    "button_save_membership": {"ru": "Сохранить членство", "en": "Save membership"},
    # Stores list
    "create_store_title": {"ru": "Создать магазин", "en": "Create store"},
    "label_display_name": {"ru": "Отображаемое имя", "en": "Display name"},
    "label_address": {"ru": "Адрес", "en": "Address"},
    "checkbox_is_active": {"ru": "Активен", "en": "Is active"},
    "button_create": {"ru": "Создать", "en": "Create"},
    "filter_include_inactive": {"ru": "Включая неактивные", "en": "Include inactive"},
    "table_store_name": {"ru": "Название", "en": "Name"},
    "table_status": {"ru": "Статус", "en": "Status"},
    "status_active_short": {"ru": "Активен", "en": "Active"},
    "status_inactive": {"ru": "Неактивен", "en": "Inactive"},
    "empty_no_stores": {"ru": "Магазины не найдены.", "en": "No stores found."},
    # Store detail
    "section_store_summary": {"ru": "Информация о магазине", "en": "Store summary"},
    "section_edit_store": {"ru": "Редактировать магазин", "en": "Edit store"},
    "section_members": {"ru": "Участники", "en": "Members"},
    "section_store_devices": {"ru": "Устройства магазина", "en": "Store devices"},
    "label_store_id": {"ru": "ID магазина:", "en": "Store ID:"},
    "label_store_status": {"ru": "Статус:", "en": "Status:"},
    "confirm_store_update": {"ru": "Подтвердить обновление магазина", "en": "Confirm store update"},
    "button_update": {"ru": "Обновить", "en": "Update"},
    "table_user": {"ru": "Пользователь", "en": "User"},
    "table_user_id_short": {"ru": "ID пользователя", "en": "User ID"},
    "empty_no_members": {"ru": "Нет участников.", "en": "No members."},
    "add_or_update_member": {"ru": "Добавить или обновить участника", "en": "Add or update member"},
    "label_user": {"ru": "Пользователь", "en": "User"},
    "select_user_placeholder": {"ru": "Выберите пользователя...", "en": "Select user..."},
    "confirm_membership_change": {"ru": "Подтвердить изменение членства", "en": "Confirm membership change"},
    "table_device_id": {"ru": "ID устройства", "en": "Device ID"},
    "table_online": {"ru": "Онлайн", "en": "Online"},
    "table_connected": {"ru": "Подключен", "en": "Connected"},
    "table_last_seen": {"ru": "Последняя активность", "en": "Last seen"},
    "status_online": {"ru": "Онлайн", "en": "Online"},
    "status_offline": {"ru": "Оффлайн", "en": "Offline"},
    "status_connected": {"ru": "Подключен", "en": "Connected"},
    "status_disconnected": {"ru": "Отключен", "en": "Disconnected"},
    "empty_no_devices": {"ru": "Нет устройств.", "en": "No devices."},
    # Devices list
    "filter_store_placeholder": {"ru": "Все магазины", "en": "All stores"},
    "filter_by_store": {"ru": "Фильтр по магазину", "en": "Filter by store"},
    "apply_filter": {"ru": "Применить", "en": "Apply"},
    "clear_filter": {"ru": "Сбросить", "en": "Clear"},
    "empty_no_devices_global": {"ru": "Устройства не найдены.", "en": "No devices found."},
    # Device detail
    "section_device_info": {"ru": "Информация об устройстве", "en": "Device info"},
    "label_device_id": {"ru": "ID устройства:", "en": "Device ID:"},
    "label_device_store": {"ru": "Магазин:", "en": "Store:"},
    "label_device_online": {"ru": "Онлайн:", "en": "Online:"},
    "label_device_connected": {"ru": "Подключен:", "en": "Connected:"},
    "label_device_last_seen": {"ru": "Последняя активность:", "en": "Last seen:"},
    "label_enrolled_at": {"ru": "Зарегистрировано:", "en": "Enrolled at:"},
    # Enroll tokens
    "mint_token_title": {"ru": "Выпустить токен регистрации", "en": "Mint Enroll Token"},
    "label_expires_sec": {"ru": "Истекает через (сек)", "en": "Expires in seconds"},
    "label_max_uses": {"ru": "Максимум использований", "en": "Max uses"},
    "label_note": {"ru": "Примечание", "en": "Note"},
    "placeholder_note_optional": {"ru": "Необязательно", "en": "Optional"},
    "confirm_token_minting": {"ru": "Подтвердить выпуск токена", "en": "Confirm token minting"},
    "button_mint_token": {"ru": "Выпустить токен", "en": "Mint token"},
    "created_token_title": {"ru": "Созданный токен", "en": "Created token"},
    "copy_now_message": {"ru": "Этот токен показывается только сейчас. Скопируйте его сразу.", "en": "This token is shown only on this response. Copy it now."},
    "label_token_id": {"ru": "ID токена:", "en": "Token ID:"},
    "label_expires_at": {"ru": "Истекает:", "en": "Expires at:"},
    "label_max_uses_short": {"ru": "Макс. использований:", "en": "Max uses:"},
    "button_copy_token": {"ru": "Копировать", "en": "Copy"},
    "copy_success": {"ru": "Скопировано!", "en": "Copied!"},
    # Login
    "login_heading": {"ru": "Вход в OMS Admin", "en": "OMS Admin Login"},
    "label_username": {"ru": "Имя пользователя", "en": "Username"},
    "label_password": {"ru": "Пароль", "en": "Password"},
    "button_sign_in": {"ru": "Войти", "en": "Sign In"},
    "error_invalid_credentials": {"ru": "Неверное имя пользователя или пароль.", "en": "Invalid username or password."},
}


def resolve_locale(request: Request) -> str:
    """
    Resolve preferred locale with fallback to DEFAULT_LANG (ru).
    Priority:
      1) Query param ?lang=ru|en (if valid)
      2) Cookie oms_admin_ui_lang
      3) Accept-Language header (en only if explicitly English primary)
      4) DEFAULT_LANG (ru)
    """
    # 1. Query param
    q = request.query_params.get("lang", "").lower().strip()
    if q in SUPPORTED:
        return q

    # 2. Cookie
    cookie_lang = request.cookies.get(LANG_COOKIE, "").lower().strip()
    if cookie_lang in SUPPORTED:
        return cookie_lang

    # 3. Accept-Language
    accept_lang = request.headers.get("accept-language", "").lower().strip()
    # Take first tag before comma/semicolon, ignoring quality values
    if accept_lang:
        first = accept_lang.split(",")[0].split(";")[0].strip()
        # Only treat as English if primary tag is clearly en/english
        if first.startswith("en"):
            return "en"

    # 4. Default
    return DEFAULT_LANG


def translate(locale: str, key: str, **kwargs) -> str:
    """Return localized string; missing keys render as key name with underscores for visibility."""
    if locale not in SUPPORTED:
        locale = DEFAULT_LANG
    entry = CATALOG.get(key, {})
    text = entry.get(locale) or entry.get(DEFAULT_LANG) or key.replace("_", " ")
    if kwargs:
        try:
            return text.format(**kwargs)
        except Exception:
            return text
    return text


# Jinja callable helpers (bound to request)
def make_translate_for(locale: str):
    def t(key: str, **kwargs) -> str:
        return translate(locale, key, **kwargs)
    return t


def _is_safe_admin_path(path: str) -> bool:
    """Ensure redirect target stays within /admin and avoids open redirect."""
    if not path:
        return False
    path = path.strip()
    if not path.startswith("/admin"):
        return False
    # Reject protocol-relative or absolute URLs injected via path
    if path.startswith("//"):
        return False
    return True


@router.get("/set-language")
def set_language(request: Request, lang: str = "ru", next: str = "/admin") -> RedirectResponse:
    """Set language cookie and redirect safely back to admin."""
    lang = lang.lower().strip()
    if lang not in SUPPORTED:
        lang = DEFAULT_LANG
    if not _is_safe_admin_path(next):
        next = "/admin"
    resp = RedirectResponse(url=next, status_code=303)
    resp.set_cookie(
        key=LANG_COOKIE,
        value=lang,
        max_age=60 * 60 * 24 * 365,  # 1 year
        path="/",
        httponly=True,
        samesite="lax",
    )
    return resp
