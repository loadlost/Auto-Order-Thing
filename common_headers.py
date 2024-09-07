# Модуль common_headers.py содержит заголовки сессии (session_headers) и общие заголовки для запросов
# с одинаковыми параметрами.


session_headers = {
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'ru,en;q=0.9,en-GB;q=0.8,en-US;q=0.7',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0',
            'sec-ch-ua': '"Not)A;Brand";v="99", "Microsoft Edge";v="127", "Chromium";v="127"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }


common_headers_config_login_information_roles_profile_info = {
    'Accept': 'application/json, text/plain, */*',
    'Host': 'lk.rosreestr.ru',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Referer': 'https://lk.rosreestr.ru/login?redirect=%2F'
}

common_headers_client_secret_rosreestr_login = {
        'Host': 'esia.gosuslugi.ru',
        'Referer': 'https://lk.rosreestr.ru/',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'cross-site',
        'Upgrade-Insecure-Requests': '1',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                  'application/signed-exchange;v=b3;q=0.7'
    }

common_headers_script_captcha_ma_plugin = {
        'Host': 'esia.gosuslugi.ru',
        'Referer': 'https://esia.gosuslugi.ru/login',
        'Sec-Fetch-Dest': 'script',
        'Sec-Fetch-Mode': 'no-cors',
        'Sec-Fetch-Site': 'same-origin',
        'Accept': '*/*'
    }

common_headers_fhp_ondate_pwd = {
        'Accept': 'application/json, text/plain, */*',
        'Host': 'esia.gosuslugi.ru',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'Referer': 'https://esia.gosuslugi.ru/login'
    }

common_headers_login_POST_totp = {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=UTF-8',
        'Host': 'esia.gosuslugi.ru',
        'Origin': 'https://esia.gosuslugi.ru',
        'Referer': 'https://esia.gosuslugi.ru/login/'
    }

common_headers_applications_information_track = {
        'Accept': 'application/json, text/plain, */*',
        'Host': 'lk.rosreestr.ru',
        'Referer': 'https://lk.rosreestr.ru/my-applications',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
    }

common_headers_info_access_key_track_png_current_user = {
        'Accept': 'application/json, text/plain, */*',
        'Host': 'lk.rosreestr.ru',
        'Referer': 'https://lk.rosreestr.ru/request-access-egrn/property-search',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
    }

common_headers_on_with_addresses = {
        'Accept': 'application/json, text/plain, */*',
        'Host': 'lk.rosreestr.ru',
        'Origin': 'https://lk.rosreestr.ru',
        'Referer': 'https://lk.rosreestr.ru/request-access-egrn/property-search',
        'Content-Type': 'application/json;charset=UTF-8',
        'Content-Length': '63',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
    }
