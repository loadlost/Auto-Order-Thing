import time
import requests
import logging
import urllib3

from classes import CustomSession
from requests_config import *
from credentials import proxy_url
from common_headers import session_headers

formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s',
                              datefmt='%d-%m-%Y %H:%M:%S')

handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.INFO)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def send_requests(session, request_list, max_url_length=100, url='Unknown URL'):
    # Функция send_requests принимает сессию и список запросов. Выполняет каждый запрос из списка и логирует результат.
    # В случае успешного ответа (коды 200, 202, 302, 401, 404) логирует успешное выполнение.
    # В случае ошибки логирует её и вызывает исключение.

    # Коды успешных ответов. Да, 404 тоже сойдёт. В некоторых случаях.
    successful_codes = [200, 202, 302, 401, 404]
    for request_config in request_list:
        try:
            # Выполняет запрос, используя конфигурацию request_config.
            response = request_config.execute(session)
            url = request_config.url if hasattr(request_config, 'url') else 'Unknown URL'

            # Если URL слишком длинный, обрезает его до max_url_length. Чтобы логи выгладили нормально.
            if len(url) > max_url_length:
                url = url[:max_url_length] + '...'

            if response.status_code in successful_codes:
                logger.info(f'{response.status_code} Request successful {url}')
            else:
                response_text = response.text if hasattr(response, 'text') else 'No response text'
                logger.error(f'{response.status_code} Request failed {url} TEXT: {response_text}')
                raise Exception
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed {url} with error: {e}")
            raise


def login(session):
    # Функция login выполняет процесс входа в систему. Она последовательно выполняет набор запросов (login_sequence)
    # через сессию и логирует успех или ошибку. В случае ошибки вызывает исключение.

    logger.info('Login process started')
    login_sequence = [
        initial_response,
        rosreestr_config_response,
        login_information_response,
        roles_response,
        login_redirect_response,
        client_secret_redirect_response,
        rosreestr_login_response,
        script_response,
        schema_response,
        gosuslugi_login_response,
        captcha_response,
        ma_plugin_response,
        gosuslugi_config_response,
        fhp_response,
        ondate_response,
        pwd_check_response,
        banners_response,
        pixel_response,
        login_POST_response,
        totp_response,
        auth_process_response,
        rosreestr_config_response,
        roles_response,
        response_profile_info,
        roles_response,
        applications_information_response,
        track_response,
        property_search_response
    ]

    try:
        send_requests(session, login_sequence)
        logger.info('Login process completed successfully')
    except Exception as e:
        logger.error(f'Login process failed with error: {e}')
        raise


def order(session):
    # Функция order выполняет процесс заказа. Она последовательно выполняет набор запросов (order_sequence)
    # через сессию и логирует успех или ошибку. В случае ошибки вызывает исключение.

    logger.info('Order process started')

    order_sequence = [
        info_response,
        access_key_response,
        on_response,
        track_png_response,
        access_key_response,
        with_addresses_response,
        current_user_response,
        statement_upload_response,
        response_finish
    ]

    try:
        send_requests(session, order_sequence)
        logger.info(f'Successfully order {RequestConfig.cad_number}')
    except Exception as e:
        logger.error(f'Order process failed with error: {e}')
        raise


def main():
    # Функция main запускает основной процесс заказа кадастровых данных. Она инициализирует сессию, выполняет вход,
    # затем обрабатывает список кадастровых номеров, вызывая функцию order для каждого. В конце сессия закрывается,
    # и логируется завершение процесса.

    logger.info('Starting main process for ordering cadastral data')

    cad_list = ['77:01:0002018:24',
                '77:01:0002018:1059',
                '77:01:0002005:2244',
                '77:01:0002018:2945',
                '77:01:0002018:2946',
                '77:01:0002018:2947',
                '77:01:0002018:2953',
                '77:01:0002018:2954',
                '77:01:0002018:2955',
                '77:01:0002018:2956',
                '77:01:0002018:2957',
                '77:01:0002018:2958']

    logger.info(f'Cadastral numbers for ordering: {cad_list}')

    with CustomSession() as session:
        session.headers.update(session_headers)

        session.proxies.update({
            'http': proxy_url,
            'https': proxy_url
        })

    login(session)

    for cad in cad_list:
        logger.info(f'Processing cadastral number: {cad}')
        RequestConfig.cad_number = cad
        order(session)
        time.sleep(10)
        logger.info('Order process completed successfully')

    session.close()
    logger.info('Finished main process for ordering cadastral data')


if __name__ == "__main__":
    main()
