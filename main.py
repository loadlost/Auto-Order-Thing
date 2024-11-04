import os
import time

import requests
import logging
import urllib3
from typing import List

from classes import CustomSession
from requests_config import *
from credentials import proxy_url
from common_headers import session_headers

# Настройка форматтера для логов
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s',
                              datefmt='%d-%m-%Y %H:%M:%S')

handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.INFO)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_session() -> CustomSession:
    """
    Инициализирует и возвращает сессию с обновленными заголовками и прокси.

    Функция создает экземпляр CustomSession, обновляет его заголовки
    и прокси, после чего возвращает готовую сессию.

    Заголовки берутся из глобальной переменной session_headers (определена в модуле common_headers).
    Прокси устанавливаются на основе глобальной переменной proxy_url (определена в модуле credentials).


    :return:  Сессия с обновленными заголовками и прокси
    :rtype: CustomSession
    :raises: None
    """
    # Инициализация сессии
    with CustomSession() as session:
        # Обновляем заголовки сессии из common_headers
        session.headers.update(session_headers)

        # Настраиваем прокси из credentials
        session.proxies.update({
            'http': proxy_url,
            'https': proxy_url
        })

    return session


def test_session(session: CustomSession) -> bool:
    """
    Проверяет, успешна ли сессия на основе выполнения запроса count_response.

    Функция отправляет запрос на получение количества непрочитанных уведомлений,
    используя объект count_response. Возвращает True, если запрос выполнен успешно
    (статус-код 200), иначе возвращает False.

    Если происходит ошибка соединения, тайм-аут или другая ошибка запроса,
    функция логирует ошибку и возвращает False.

    count_response задается в модуле requests_config.

    :param session: Активная сессия для выполнения запроса.
    :type session: CustomSession
    :return: Возвращает True, если запрос успешен, иначе False.
    :rtype: Bool
    :raises: None
    """
    try:
        # Выполняем запрос для проверки сессии
        test_response: requests.Response = count_response.execute(session)

        # Проверяем успешность ответа
        if test_response.status_code == 200:
            return True
        else:
            logger.warning(f"Unexpected status code: {test_response.status_code}")
            return False
    except requests.exceptions.Timeout:
        # Логируем тайм-аут запроса
        logger.error("Request timed out.")
        return False
    except requests.exceptions.ConnectionError as ce:
        # Логируем ошибку соединения
        logger.error(f"Connection error occurred: {ce}")
        return False
    except requests.exceptions.RequestException as e:
        # Логируем общую ошибку запроса
        logger.error(f"An error occurred during the request: {e}")
        return False

def login(session):
    """
    Выполняет процесс авторизации, отправляя последовательность HTTP-запросов.

    Функция запускает серию запросов для процесса авторизации, используя
    предварительно настроенную сессию. Последовательность запросов включает
    этапы от начального запроса до получения профиля пользователя.

    :param session: Активная сессия для выполнения запроса.
    :type session: CustomSession
    :return: None
    :rtype: None
    :raises requests.exceptions.RequestException: Возникает при неудачном выполнении одного из запросов из login_sequence
    """

    logger.info('Login process started')

    # Список с объектами класса RequestConfig, которые содержат параметры запросов
    # Объекты RequestConfig определены в модуле requests_config
    login_sequence: List[RequestConfig] = [
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
        login_POST_response,
        totp_response,
        auth_process_response,
        rosreestr_config_response,
        roles_response,
        response_profile_info,
        roles_response,
        applications_information_response,
        track_response
    ]

    try:
        # Выполнение последовательности запросов
        send_requests(session, login_sequence)
        logger.info('Login process completed successfully')
    except requests.exceptions.RequestException as e:
        raise requests.exceptions.RequestException('Login process failed with error: ' + str(e))


def order(session: CustomSession, cad_list: List[str]) -> None:
    """
    Выполняет процесс заказа для списка кадастровых номеров.

    Функция заказывает каждый кадастровый номер в списке,
    используя последовательность запросов order_sequence, и ждёт 10 секунд перед
    обработкой следующего номера.

    :param session: Активная сессия для выполнения запросов.
    :type session: CustomSession
    :param cad_list: Список кадастровых номеров для обработки.
    :type cad_list: List[str]
    :return: None
    :rtype: None
    :raises requests.exceptions.RequestException: Возникает при неудачном выполнении запроса или других ошибках в процессе заказа.
    """
    logger.info('Order process started')

    # Список с объектами класса RequestConfig, которые содержат параметры запросов
    order_sequence: List[RequestConfig] = [
        property_search_response,
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

    logger.info(f'Cadastral numbers for ordering: {cad_list}')

    for cad in cad_list:
        logger.info(f'Processing cadastral number: {cad}')
        # Устанавливаем текущий кадастровый номер для RequestConfig
        RequestConfig.cad_number = cad
        try:
            # Отправляем запросы из order_sequence
            send_requests(session, order_sequence)
            logger.info(f'Successfully ordered {RequestConfig.cad_number}')
        except (requests.exceptions.RequestException, Exception) as e:
            # Поднимаем исключение с сообщением об ошибке
            raise requests.exceptions.RequestException('Order process failed with error: ' + str(e))
        else:
            # Если запрос успешен, ждем перед следующим заказом
            logger.info('Order process completed successfully, waiting for 10 seconds to next order')
            time.sleep(10)

def download_file(session: CustomSession, cad_list: List[str], task_name: str) -> None:
    """
    Скачивает файлы для списка кадастровых номеров и сохраняет их в указанную папку.

    Функция выполняет запросы для каждого кадастрового номера в списке cad_list,
    скачивает связанные файлы и сохраняет их в папку "output/{task_name}".

    :param session: Активная сессия для выполнения запросов.
    :type session: CustomSession
    :param cad_list: Список кадастровых номеров для обработки.
    :type cad_list: List[str]
    :param task_name: Имя задачи, используемое для именования папки.
    :type task_name: str
    :return: None
    :rtype: None
    :raises requests.exceptions.RequestException: Возникает при неудачном выполнении запроса.
    """
    # Выполняем запрос на получение доступа
    access_key_response.execute(session)

    for cad in cad_list:
        logger.info(f"Downloading file: {cad}")
        # Устанавливаем текущий кадастровый номер для RequestConfig
        RequestConfig.cad_number = cad
        # Выполняем запрос для страницы
        page_response.execute(session)

        # Проверяем, есть ли ссылка для скачивания
        if RequestConfig.download_link is not None:
            logger.info(f"RequestConfig.download_link: {RequestConfig.download_link}")
            # Выполняем запрос для скачивания файла
            zipfile = download_response.execute(session)

            # Задаём путь к папке для сохранения файлов
            output_dir: str = os.path.join("output", task_name)
            # Создаем папку, если она не существует
            os.makedirs(output_dir, exist_ok=True)

            # Формируем имя файла, заменяя двоеточия на "x"
            file_name = cad.replace(":", "x") + ".zip"
            # Формируем полный путь к файлу
            file_path = os.path.join(output_dir, file_name)

            # Если это последний кадастровый номер, логируем завершение
            if cad == cad_list[-1]:
                logging.info(f"All files downloaded. Output folder: {output_dir}")

            # Сохраняем скачанный файл
            with open(file_path, 'wb') as file:
                logger.info(f"file_path: {file_path}")
                file.write(zipfile.content)
        else:
            # Если ссылка на скачивание отсутствует
            logger.info(f"RequestConfig.download_link is None. Skipping download.")

    logging.info("Download process completed.")





def send_requests(session: CustomSession, request_list: List[RequestConfig], max_url_length: int = 100,
                  url: str = 'Unknown URL') -> None:
    """
    Выполняет последовательность HTTP-запросов, используя CustomSession.

    Функция проходит по списку запросов, выполняя их через сессию.
    Логирует успешные и неуспешные запросы, ограничивает длину URL до max_url_length.
    При возникновении ошибки запросов вызывает исключение.

    :param session: Активная сессия для выполнения запросов.
    :type session: CustomSession
    :param request_list: Список объектов RequestConfig с конфигурациями запросов.
    :type request_list: List[RequestConfig]
    :param max_url_length: Максимальная длина отображаемого URL для логирования (по умолчанию 100).
    :type max_url_length: int
    :param url: URL для логирования в случае отсутствия URL в запросе.
    :type url: str
    :return: None
    :rtype: None
    :raises requests.exceptions.RequestException: Поднимает исключение в случае ошибки запроса.
    """
    successful_codes: List[int] = [200, 202, 302, 401, 404]

    for request_config in request_list:
        try:
            # Выполняем запрос используя параметры запросов из объектов класса RequestConfig и метод RequestConfig.execute
            response: requests.Response = request_config.execute(session)
            # Проверяем наличие URL в конфигурации запроса. Используется в логах.
            url: str = request_config.url if hasattr(request_config, 'url') else 'Unknown URL'

            # Ограничиваем длину URL для логирования
            if len(url) > max_url_length:
                url: str = url[:max_url_length] + '...'

            # Проверяем, является ли статус-код успешным
            if response.status_code in successful_codes:
                logger.info(f'{response.status_code} Request successful {url}')
            else:
                # Логируем и вызываем исключение, если запрос неуспешен
                response_text: str = response.text if hasattr(response, 'text') else 'No response text'
                logger.error(f'{response.status_code} Request failed {url} TEXT: {response_text}')
                raise requests.exceptions.RequestException(
                    'Request failed with status code: ' + str(response.status_code))
        except requests.exceptions.RequestException as e:
            # Логируем ошибку и поднимаем исключение с дополнительной информацией
            logger.error(f"Request failed {url} with error: {e}")
            raise requests.exceptions.RequestException('Request failed with error: ' + str(e))


def test():
    # Пример использования всех функций модуля:
    def get_session_test():
        # 1. Получаем сессию
        return get_session()

    def login_test(session):
        # 2. Выполняем процесс авторизации
        try:
            login(session)
            logger.info("Authorization successful.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during authorization: {e}")
            exit(1)
    def test_session_test(session):
        # 3. Проверяем, что сессия активна
        if test_session(session):
            logger.info("Session is active.")
        else:
            logger.error("Error: Session is not active.")
            exit(1)
    def order_test(session):
        # 4. Выполняем заказы по списку кадастровых номеров
        cad_list = ['77:01:0004011:5040', '77:01:0004011:5041']  # Пример списка кадастровых номеров
        try:
            order(session, cad_list)
            logger.info("Order process completed successfully.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during order process: {e}")
            exit(1)

    def download_file_test(session, cad_list):
        # 5. Скачиваем файлы по результатам заказа
        task_name = "task_001"  # Имя задачи для сохранения файлов
        try:
            download_file(session, cad_list, task_name)
        except requests.exceptions.RequestException as e:
            logger.error(f"Error during file download: {e}")

    session_for_test = get_session_test()
    login_test(session_for_test)
    test_session_test(session_for_test)
    order_test(session_for_test)
    download_file_test(session_for_test, ['77:01:0004011:1097'])


if __name__ == '__main__':
    # test()
    pass
