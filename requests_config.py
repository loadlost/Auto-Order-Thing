# Модуль requests_config.py содержит объекты конфигурации запросов, каждый из которых представляет собой экземпляр
# класса RequestConfig.
#
# Объект RequestConfig включает следующие параметры:
# - url: URL, на который будет отправлен запрос.
# - method: HTTP-метод (GET, POST и т.д.).
# - headers: Заголовки запроса.
# - before_request_method: Метод, который выполняется перед отправкой запроса для подготовки данных.
# - after_request_method: Метод, который выполняется после получения ответа для обработки данных.
# - data: Данные для POST-запросов.
# - allow_redirects: Флаг, определяющий, разрешены ли автоматические редиректы.
# - use_proxies: Флаг, определяющий, нужно ли использовать прокси для запроса.
# - solver: Объект GOSSolver, используемый для выполнения запросов.


from credentials import login_pass_gosuslugi
from classes import RequestConfig, GOSSolver
import common_headers

initial_response = RequestConfig(
    url='https://lk.rosreestr.ru/',
    method='GET',
    headers={
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8, '
                  'application/signed-exchange;v=b3;q=0.7',
        'Host': 'lk.rosreestr.ru',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1'
    }
)

rosreestr_config_response = RequestConfig(
    url="https://lk.rosreestr.ru/account-back/config",
    method='GET',
    headers=common_headers.common_headers_config_login_information_roles_profile_info
)

login_information_response = RequestConfig(
    url='https://lk.rosreestr.ru/account-back/access-key/cancellation/status/information',
    method='GET',
    headers=common_headers.common_headers_config_login_information_roles_profile_info
)

roles_response = RequestConfig(
    url='https://lk.rosreestr.ru/account-back/profile/roles',
    method='GET',
    headers=common_headers.common_headers_config_login_information_roles_profile_info,
    after_request_method='process_roles_response'
)

login_redirect_response = RequestConfig(
    url='https://lk.rosreestr.ru/account-back/auth/login?homeUrl=https%3A%2F%2Flk.rosreestr.ru%2Flogin%3Fredirect%3D'
        '%252F',
    method='GET',
    headers={
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                  'application/signed-exchange;v=b3;q=0.7',
        'Host': 'lk.rosreestr.ru',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://lk.rosreestr.ru/login?redirect=%2F'
    },
    allow_redirects=False,
    after_request_method='extract_url_from_headers'
)

client_secret_redirect_response = RequestConfig(
    method='GET',
    headers=common_headers.common_headers_client_secret_rosreestr_login,
    allow_redirects=False,
    use_proxies=False,
    before_request_method='set_url_from_login_redirect'
)

rosreestr_login_response = RequestConfig(
    url='https://esia.gosuslugi.ru/login',
    method='GET',
    headers=common_headers.common_headers_client_secret_rosreestr_login,
    use_proxies=False
)

script_response = RequestConfig(
    url='https://esia.gosuslugi.ru/__jsch/static/script.js',
    method='GET',
    headers=common_headers.common_headers_script_captcha_ma_plugin,
    use_proxies=False
)

schema_response = RequestConfig(
    url='https://esia.gosuslugi.ru/__jsch/schema.json',
    method='GET',
    headers={
        'Host': 'esia.gosuslugi.ru',
        'Referer': 'https://esia.gosuslugi.ru/login',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'Accept': '*/*',
        'Content-Type': 'application/json;charset=UTF-8'
    },
    use_proxies=False,
    solver=GOSSolver(),
    after_request_method='handle_schema_response'
)

gosuslugi_login_response = RequestConfig(
    url='https://esia.gosuslugi.ru/login',
    method='GET',
    headers={
        'Host': 'esia.gosuslugi.ru',
        'Referer': 'https://esia.gosuslugi.ru/login',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                  'application/signed-exchange;v=b3;q=0.7'
    },
    use_proxies=False
)

captcha_response = RequestConfig(
    url='https://esia.gosuslugi.ru/captcha-plugin/static/',
    method='GET',
    headers=common_headers.common_headers_script_captcha_ma_plugin,
    use_proxies=False
)

ma_plugin_response = RequestConfig(
    url='https://esia.gosuslugi.ru/ma-plugin/static/',
    method='GET',
    headers=common_headers.common_headers_script_captcha_ma_plugin,
    use_proxies=False
)

gosuslugi_config_response = RequestConfig(
    url='https://esia.gosuslugi.ru/aas/oauth2/config',
    method='GET',
    headers={
        'Host': 'esia.gosuslugi.ru',
        'Referer': 'https://esia.gosuslugi.ru/login',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=UTF-8'
    },
    use_proxies=False
)

fhp_response = RequestConfig(
    url='https://esia.gosuslugi.ru/esia-rs/api/public/v1/config/fhp',
    method='GET',
    headers=common_headers.common_headers_fhp_ondate_pwd,
    use_proxies=False
)

ondate_response = RequestConfig(
    url='https://esia.gosuslugi.ru/rs/dscl?ondate=24-08-2024_20-26-05',
    method='GET',
    headers=common_headers.common_headers_fhp_ondate_pwd,
    use_proxies=False
)

pwd_check_response = RequestConfig(
    url='https://esia.gosuslugi.ru/esia-rs/api/public/v1/pwd/check?lang=ru',
    method='GET',
    headers=common_headers.common_headers_fhp_ondate_pwd,
    use_proxies=False
)

banners_response = RequestConfig(
    url='https://www.gosuslugi.ru/api/quadrupel/v1/banners?platform=EPGUV3_DESK&groups=esia_noAuth',
    method='GET',
    headers={
        'Accept': 'application/json, text/plain, */*',
        'Host': 'www.gosuslugi.ru',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'cross-site',
        'Referer': 'https://esia.gosuslugi.ru/login'
    },
    use_proxies=False
)

login_POST_response = RequestConfig(
    url='https://esia.gosuslugi.ru/aas/oauth2/api/login',
    method='POST',
    headers=common_headers.common_headers_login_POST_totp,
    data=login_pass_gosuslugi,
    use_proxies=False
)

totp_response = RequestConfig(
    method='POST',
    headers=common_headers.common_headers_login_POST_totp,
    use_proxies=False,
    before_request_method='set_totp_url',
    after_request_method='extract_redirect_url'
)

auth_process_response = RequestConfig(
    method='GET',
    headers={
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                  'application/signed-exchange;v=b3;q=0.7',
        'Host': 'lk.rosreestr.ru',
        'Referer': 'https://esia.gosuslugi.ru/login/',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'cross-site',
        'Upgrade-Insecure-Requests': '1'
    },
    before_request_method='set_auth_process_url'
)

response_profile_info = RequestConfig(
    method='GET',
    headers=common_headers.common_headers_config_login_information_roles_profile_info,
    before_request_method='set_oid_url'
)


applications_information_response = RequestConfig(
    url='https://lk.rosreestr.ru/account-back/access-key/cancellation/status/information',
    method='GET',
    headers=common_headers.common_headers_applications_information_track
)

track_response = RequestConfig(
    url='https://lk.rosreestr.ru/track.png?a=service-start&s=ls-graph-service&o=&f=page&c=',
    method='GET',
    headers=common_headers.common_headers_applications_information_track
)

property_search_response = RequestConfig(
    url='https://lk.rosreestr.ru/request-access-egrn/property-search',
    method='GET',
    headers={
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                  'application/signed-exchange;v=b3;q=0.7',
        'Host': 'lk.rosreestr.ru',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1'
    }
)

info_response = RequestConfig(
    url='https://lk.rosreestr.ru/account-back/profile/info',
    method='GET',
    headers=common_headers.common_headers_info_access_key_track_png_current_user,
    after_request_method='process_info_response'
)

access_key_response = RequestConfig(
    url='https://lk.rosreestr.ru/account-back/access-key',
    method='GET',
    headers=common_headers.common_headers_info_access_key_track_png_current_user,
    after_request_method='extract_access_key'
)

on_response = RequestConfig(
    url='https://lk.rosreestr.ru/account-back/on',
    method='POST',
    headers=common_headers.common_headers_on_with_addresses,
    before_request_method='set_on_response_data',
    after_request_method='process_on_response'

)

track_png_response = RequestConfig(
    method='GET',
    headers=common_headers.common_headers_info_access_key_track_png_current_user,
    before_request_method='set_track_png_url'
)

with_addresses_response = RequestConfig(
    url='https://lk.rosreestr.ru/account-back/on/with-addresses',
    method='POST',
    headers=common_headers.common_headers_on_with_addresses,
    before_request_method='set_with_addresses_data'
)

current_user_response = RequestConfig(
    url='https://lk.rosreestr.ru/account-back/access-key/current-user',
    method='GET',
    headers=common_headers.common_headers_info_access_key_track_png_current_user
)

statement_upload_response = RequestConfig(
    url='https://lk.rosreestr.ru/account-request/statement/upload',
    method='POST',
    headers={
        'Accept': 'application/json, text/plain, */*',
        'Host': 'lk.rosreestr.ru',
        'Origin': 'https://lk.rosreestr.ru',
        'Referer': 'https://lk.rosreestr.ru/request-access-egrn/property-search',
        'Content-Type': 'application/json;charset=UTF-8',
        'Content-Length': '1620',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
    },
    before_request_method='set_statement_upload_data',
    after_request_method='process_statement_upload_response'
)

response_finish = RequestConfig(
    url="https://lk.rosreestr.ru/account-request/statement/finish",
    method='POST',
    headers={
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=UTF-8',
        'Host': 'lk.rosreestr.ru',
        'Origin': 'https://lk.rosreestr.ru',
        'Referer': 'https://lk.rosreestr.ru/request-access-egrn/property-search',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
    },
    before_request_method='set_response_finish_data'
)
page_response = RequestConfig(
    url="https://lk.rosreestr.ru/account-back/applications?page=0&size=10",
    method='POST',
    headers={
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=UTF-8',
        'Host': 'lk.rosreestr.ru',
        'Origin': 'https://lk.rosreestr.ru',
        'Referer': 'https://lk.rosreestr.ru/request-access-egrn/property-search',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
    },
    before_request_method='set_page_response_data',
    after_request_method='get_link_to_download'
)

download_response = RequestConfig(
    method='GET',
    headers={
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=UTF-8',
        'Host': 'lk.rosreestr.ru',
        'Origin': 'https://lk.rosreestr.ru',
        'Referer': 'https://lk.rosreestr.ru/request-access-egrn/property-search',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
    },
    before_request_method='set_download_response_url'
)

count_response = RequestConfig(
    url='https://lk.rosreestr.ru/account-back/notifications/unread/count',
    method='GET',
    headers={
        'Accept': 'application/json, text/plain, */*',
        'Host': 'lk.rosreestr.ru',
        'Referer': 'https://lk.rosreestr.ru/success',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
    }
)
