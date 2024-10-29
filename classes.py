import json
import logging
import time
import uuid
from hashlib import md5
from typing import Optional, Tuple, Dict, Callable, Any
from zlib import crc32

import pyotp
import requests
from requests import Response

from credentials import totp_secret

logger = logging.getLogger(__name__)


class RequestConfig:
    """
    Класс для конфигурирования и выполнения HTTP-запросов.

    Attributes:
        url_from_location (Optional[str]): URL для редиректа.
        url_from_redirect_url (Optional[str]): URL для редиректа.
        document (Optional[Dict]): Словарь, содержащий информацию о документе заявителя.
        cad_number (Optional[str]): Кадастровый номер, используемый для запросов.
        element (Optional[Dict]): Словарь, содержащий информацию об объекте.
        attributes (Optional[Dict]): Атрибуты, содержащие информацию о заявителе.
        esiaUserId (Optional[str]): Идентификатор пользователя в системе ЕСИА.
        accessKey (Optional[str]): Ключ доступа для выполнения операций.
        superPackageGuid (Optional[str]): Уникальный идентификатор пакета.
        download_link (Optional[str]): Ссылка для скачивания файла.

    Methods:
        execute(session: requests.Session) -> requests.Response:
        Выполняет запрос на основе конфигурации объекта RequestConfig, используя указанную сессию
    """

    url_from_location: Optional[str] = None  # Заполняется в методе extract_url_from_headers
    url_from_redirect_url: Optional[str] = None  # Заполняется в методе extract_redirect_url

    # Заполняется в методе process_info_response. document должен содержать значения:
    # series - серия паспорта, number - номер паспорта, issueDate - дата выдачи паспорта, issuedBy - кем выдан паспорт
    document: Optional[Dict] = None  #

    cad_number: Optional[str] = None  # Заполняется в main

    # Заполняется в методе process_info_response. element должен содержать значения:
    # objType - тип объекта, propertyValue - размер, unittypearea - единица измерения
    element: Optional[Dict] = None

    # Заполняется в методе process_info_response. attributes должен содержать значения:
    # linkEmail - почта, firstname - имя, surname - фамилия, patronymic - отчество, countryInformation - страна,
    # snils - СНИЛС, email - почта, phoneNumber - телефон, addresses - адрес
    attributes: Optional[Dict] = None

    esiaUserId: Optional[str] = None  # Заполняется в методе process_statement_upload_response
    accessKey: Optional[str] = None  # Заполняется в методе extract_access_key
    superPackageGuid: Optional[str] = None  # Заполняется в методе process_statement_upload_response
    download_link: Optional[str] = None  # Заполняется в методе get_link_to_download

    def __init__(self, url: Optional[str] = None, method: str = 'GET', headers: Optional[Dict[str, str]] = None,
                 data: Optional[Dict] = None, allow_redirects: bool = True, use_proxies: bool = True,
                 before_request_method: Optional[str] = None, after_request_method: Optional[str] = None,
                 solver=None):

        """
        Инициализирует объект RequestConfig для выполнения HTTP-запросов.

        :param url: URL запроса. Если не указан, используется None.
        :type url: Optional[str]

        :param method: Метод запроса ('GET' или 'POST'). По умолчанию 'GET'.
        :type method: str

        :param headers: Заголовки для запроса. Если не указаны, создается пустой словарь.
        :type headers: Optional[Dict[str, str]]

        :param data: Данные для POST-запросов. Если не указаны, используется None.
        :type data: Optional[Dict]

        :param allow_redirects: Определяет, разрешены ли автоматические редиректы. По умолчанию True.
        :type allow_redirects: bool

        :param use_proxies: Указывает, нужно ли использовать прокси для запроса. По умолчанию True.
        :type use_proxies: bool

        :param before_request_method: Имя метода, который будет выполнен перед отправкой запроса. Может быть None.
        :type before_request_method: Optional[str]

        :param after_request_method: Имя метода, который будет выполнен после получения ответа. Может быть None.
        :type after_request_method: Optional[str]

        :param solver: Объект для обхода проверки на ботов. Может быть None.
        :type solver: Optional[GOSSolver]
        """

        # URL запроса
        self.url: Optional[str] = url

        # Метод (GET или POST)
        self.method: str = method

        # Заголовки запроса, если не переданы — создается пустой словарь
        self.headers: Dict[str, str] = headers if headers else {}

        # Данные для POST-запросов, могут быть None
        self.data: Optional[Dict] = data

        # Определяет, будут ли автоматически обрабатываться редиректы
        self.allow_redirects: bool = allow_redirects

        # Указывает, использовать ли прокси для запросов. Если False, то прокси не будет использован для всех запросов.
        # Если True, то прокси будет использован для всех запросов. Если use_proxies, то значение берётся из
        # конфигурации запроса. (из объектов RequestConfig в requests_config.py)
        self.use_proxies: bool = use_proxies

        # Метод, который будет выполнен перед отправкой запроса (может быть None)
        self.before_request_method: Optional[str] = before_request_method

        # Метод, который будет выполнен после получения ответа (может быть None)
        self.after_request_method: Optional[str] = after_request_method

        # Сессия, используемая для выполнения запроса, инициализируется позже (requests.Session)
        self.session: Optional[requests.Session] = None

        # Solver используется для обхода проверки на ботов, может быть None
        self.solver = solver

    def execute(self, session: requests.Session) -> requests.Response:
        """
        Выполняет запрос, используя requests.Session и конфигурацию объекта RequestConfig.

        Метод поддерживает выполнение GET и POST запросов. Если указан метод before_request_method,
        он будет выполнен перед отправкой запроса. Аналогично, after_request_method выполняется
        после получения ответа, и, если он возвращает новый ответ, то этот новый ответ будет возвращён.

        :param session: Активная сессия requests.Session для выполнения запроса.
        :type session: requests.Session
        :return: Ответ от сервера в виде объекта requests.Response. Если метод after_request_method возвращает
                 новый response, то именно он будет возвращён.
        :rtype: requests.Response
        :raises ValueError: Если указан неподдерживаемый HTTP-метод (не GET и не POST).
        """

        logger.info(f'Executing {self.method} request to {self.url}')

        self.session: requests.Session = session  # Сохраняет текущую сессию для использования в других методах

        if self.before_request_method:
            # Если указан метод, который должен выполняться перед запросом,
            # получает ссылку на этот метод и вызывает его, если он существует и может быть вызван.
            method_to_call: Optional[Callable] = getattr(self, self.before_request_method, None)
            if callable(method_to_call):
                method_to_call()  # Вызывает метод для подготовки данных перед выполнением запроса

        proxies: Dict[str, str] = session.proxies if self.use_proxies else {"http": "", "https": ""}
        # Если флаг self.use_proxies True (по умолчанию), используется прокси из сессии.
        # Если False, прокси не используется.

        if self.method.upper() == 'GET':
            # Выполняет GET запрос с указанными параметрами.
            response: requests.Response = session.get(self.url, headers=self.headers, allow_redirects=self.allow_redirects,
                                   proxies=proxies)
        elif self.method.upper() == 'POST':
            # Выполняет POST запрос с указанными параметрами и данными.
            response: requests.Response = session.post(self.url, headers=self.headers, json=self.data,
                                    allow_redirects=self.allow_redirects, proxies=proxies)
        else:
            # Выбрасывает исключение, если метод не поддерживается.
            raise ValueError(f"Unsupported method: {self.method}")

        if self.after_request_method:
            # Если указан метод для обработки ответа, вызывает его.
            method_to_call: Optional[Callable] = getattr(self, self.after_request_method, None)
            if callable(method_to_call):
                new_response: Optional[requests.Response] = method_to_call(response)
                # Если метод возвращает новый ответ, то возвращает его.
                if new_response:
                    logger.info(f'Received new response from after request method: {self.after_request_method}')
                    return new_response

        return response



    def extract_url_from_headers(self, response: requests.Response) -> None:
        """
        Извлекает URL из заголовка Location ответа и сохраняет его в атрибуте класса url_from_location.
        Выполняется после запроса login_redirect_response

        :param response: HTTP-ответ, содержащий заголовки, из которых извлекается URL.
        :type response: requests.Response
        :return: None
        """

        logger.info('Request auth/login triggered the method extract_url_from_headers')
        RequestConfig.url_from_location = response.headers.get('Location', '')

    def set_url_from_login_redirect(self) -> None:
        """
        Устанавливает значение атрибута self.url, используя URL, сохранённый в url_from_location.
        Выполняется перед запросом client_secret_redirect_response

        :return: None
        """

        logger.info('Request client_secret triggered the method set_url_from_login_redirect')
        self.url: Optional[str] = RequestConfig.url_from_location

    def handle_schema_response(self, response: requests.Response) -> None:
        """
        Обрабатывает JSON-ответ, решает задачу проверки на ботов с помощью solver и устанавливает cookies для сессии.

        Если ответ не может быть распознан как JSON, выбрасывается исключение с указанием на необходимость капчи.

        Выполняется после запроса schema_response

        :param response: HTTP-ответ, содержащий JSON-данные для обработки.
        :type response: requests.Response
        :return: None
        :raises Exception: Если ответ не является JSON и требуется капча.
        """

        logger.info('Request __jsch/schema.json triggered the method handle_schema_response')
        schema_response_content: Optional[str] = response.content
        try:
            # Пытается распарсить содержимое ответа как JSON.
            response_data: Dict[str, str] = json.loads(schema_response_content)
            user_agent: str = self.session.headers.get('User-Agent', 'Mozilla/5.0')
            cache_key: str = response_data["ip"]
            logger.info('Successfully parsed JSON from schema response')
        except json.decoder.JSONDecodeError:
            # Если распарсить не удаётся, значит, вместо JSON содержится HTML с запросом на ввод капчи
            raise Exception("Captcha!")

        logger.info('Solving challenge using solver')
        # Использует solver для решения задачи, связанной с проверкой на ботов.
        bucket_time: int
        generated_cookies: Dict[str, str]
        bucket_time, generated_cookies = self.solver.solve(user_agent, response_data, cache_key=cache_key)

        # Преобразует все значения в cookies в строковый формат
        for key in generated_cookies:
            generated_cookies[key] = str(generated_cookies[key])

        # Устанавливает сгенерированные cookies для сессии
        for key, value in generated_cookies.items():
            self.session.cookies.set(key, value, domain='esia.gosuslugi.ru')

    def set_totp_url(self) -> None:
        """
        Генерирует TOTP-код с использованием библиотеки pyotp и устанавливает URL для проверки TOTP.

        URL содержит сгенерированный TOTP-код, который используется для двухфакторной аутентификации.

        totp_secret - секрет для генерации TOTP-кода. Задан в credentials.py

        Выполняется перед totp_response

        :return: None
        """
        logger.info('Request totp/verify triggered the method set_totp_url')
        totp_code: str = pyotp.TOTP(totp_secret, digits=6, digest='sha1', interval=30).now()
        logger.info(f'Generated TOTP code: {totp_code}')
        self.url: str = f'https://esia.gosuslugi.ru/aas/oauth2/api/login/totp/verify?code={totp_code}'

    def extract_redirect_url(self, response) -> None:
        """
        Извлекает URL для редиректа из JSON-ответа и сохраняет его в атрибуте класса url_from_redirect_url.

        Выполняется после запроса totp_response

        :param response: ответ, содержащий JSON-данные, из которых извлекается URL для редиректа.
        :type response: requests.Response
        :return: None
        """
        logger.info('Request totp/verify triggered the method extract_redirect_url')
        totp_response_json: Dict[str, str] = response.json()
        RequestConfig.url_from_redirect_url = totp_response_json.get('redirect_url', '')

    def set_auth_process_url(self) -> None:
        """
        Устанавливает значение self.url, используя URL, сохранённый в url_from_redirect_url.

        Выполняется перед auth_process_response

        :return: None
        """
        logger.info('Request auth/process triggered the method set_auth_process_url')
        self.url: Optional[str] = RequestConfig.url_from_redirect_url

    def process_roles_response(self, response: requests.Response) -> None:
        """
        Извлекает oid из JSON-ответа при успешном статусе и устанавливает cookie 'PC_USER_WAS_AUTHORIZED'.

        Если пользователь не авторизован (поле 'logged' равно False), извлекается oid из поля 'roles'
        и устанавливается cookie 'PC_USER_WAS_AUTHORIZED' с доменом 'lk.rosreestr.ru'.

        Выполняется после roles_response

        :param response: HTTP-ответ с информацией о ролях пользователя.
        :type response: requests.Response
        :return: None
        """
        logger.info('Request profile/roles triggered the method process_roles_response')
        if response.status_code == 200:
            # Если статус ответа 200, парсит JSON-ответ
            logger.info('Received roles response with status 200')
            response_json: Dict[str, Any] = response.json()

            # Проверяет, авторизован ли пользователь. Если 'logged' == False, то извлекает oid
            if not response_json.get('logged', True):
                oid: str = response_json['roles'][0]['oid']

                # Устанавливает cookie 'PC_USER_WAS_AUTHORIZED' из oid
                self.session.cookies.set('PC_USER_WAS_AUTHORIZED', str(oid), domain='lk.rosreestr.ru')

    def set_oid_url(self) -> None:
        """
        Устанавливает значение self.url, используя значение oid, извлечённое из cookie 'PC_USER_WAS_AUTHORIZED'.

        URL формируется для запроса информации о профиле пользователя на основе oid.

        Выполняется перед response_profile_info
        :return: None
        """
        # Устанавливает self.url, используя значение oid из cookie 'PC_USER_WAS_AUTHORIZED'
        logger.info('Request profile/info?oid triggered the method set_oid_url')
        oid: str = self.session.cookies.get('PC_USER_WAS_AUTHORIZED')
        self.url: str = f'https://lk.rosreestr.ru/account-back/profile/info?oid={oid}'

    def process_info_response(self, response: requests.Response) -> None:
        """
        Обрабатывает JSON-ответ и сохраняет данные в RequestConfig.attributes и RequestConfig.document.

        Выполняется после response_profile_info_response

        :param response: HTTP-ответ с информацией о профиле пользователя.
        :type response: requests.Response
        :return: None
        """
        logger.info('Request profile/info?oid triggered the method process_info_response')
        info_data: Dict[str, Any] = response.json()
        RequestConfig.attributes = info_data.get("attributesOauth", {})
        RequestConfig.document = RequestConfig.attributes.get("documents", {}).get("elements", [None])[0]

    def set_on_response_data(self) -> None:
        """
        Устанавливает значение self.data, используя значение RequestConfig.cad_number

        Выполняется перед process_on_response
        :return: None
        """
        self.data: Dict[str, Any] = {
            "filterType": "cadastral",
            "cadNumbers": [RequestConfig.cad_number]
        }
        logger.info(f'Set data with cadNumber: {RequestConfig.cad_number}')

    def process_on_response(self, response: requests.Response, retry_count: int =0) -> Optional[Response]:
        """
        В случае ошибки 503 повторяет запрос до 5 раз с паузой в 10 секунд.

        Если код 503 сохраняется после 5 попыток, выбрасывается исключение. При успешном запросе
        извлекается первый элемент из response и сохраняется в атрибуте класса RequestConfig.element.

        Если код изначально 200, возвращает None.

        Выполняется после process_on_response


        :param response: HTTP-ответ от сервера.
        :type response: requests.Response
        :param retry_count: Счётчик попыток повторного запроса в случае ошибки 503 (по умолчанию 0).
        :type retry_count: int
        :return: Возвращает объект requests.Response при успешном запросе, или None.
        :rtype: Optional[requests.Response]
        :raises Exception: Если после 5 попыток ответ всё ещё содержит статус 503.
        """
        logger.info('Request account-back/on triggered the method process_on_response',
                    extra={'attempt_number': retry_count + 1})

        if response.status_code == 503:  # При статусе 503 повторяет запрос до 5 раз с паузой в 10 секунд
            if retry_count < 5:
                logger.info(
                    f'{response.status_code} Service Unavailable, retrying request. Attempt {retry_count + 1}. '
                    f'Response: {response.text}')
                time.sleep(10)
                new_response: Optional[requests.Response] = self.session.get(self.url, headers=self.headers)
                return self.process_on_response(new_response, retry_count + 1)
            else:  # Если после 5 попыток статус 503 сохраняется, выбрасывает исключение
                logger.error('Failed to retrieve data after 5 attempts due to Service Unavailable.',
                             extra={'status_code': response.status_code, 'response_text': response.text})
                raise Exception("Failed to retrieve data after 5 attempts due to Service Unavailable.")
        # Если запрос успешен, извлекает первый элемент из "elements" и сохраняет его в RequestConfig.element
        elif response.status_code == 200:
            account_back_on_data: Dict[str, Any] = response.json()
            RequestConfig.element = account_back_on_data.get("elements", [None])[0]

        # Если запрос успешен после повторных попыток, возвращает response, заменяющий исходный
        if response.status_code == 200 and retry_count > 0:
            logger.info(f'{response.status_code} Request eventually successful on attempt {retry_count + 1}.')
            return response

    def set_track_png_url(self) -> None:
        """
        Устанавливает значение self.url для запроса open-card, используя кадастровый номер.

        Выполняется перед track_png_response

        URL формируется для запроса на основе кадастрового номера,
        сохранённого в RequestConfig.cad_number.

        :return: None
        """
        logger.info('Request open-card triggered the method set_track_png_url')
        self.url: str = f'https://lk.rosreestr.ru/track.png?a=open-card&s=on&o={RequestConfig.cad_number}&f=search&c='

    def extract_access_key(self, response) -> None:
        """
        Извлекает accessKey из JSON-ответа и сохраняет его в атрибуте класса RequestConfig.accessKey.

        Выполняется после access_key_response

        :param response: HTTP-ответ, содержащий JSON-данные, из которых извлекается ключ доступа.
        :type response: requests.Response
        :return: None
        """
        logger.info('Request account-back/access-key triggered the method extract_access_key')
        RequestConfig.accessKey = response.json().get("guid", "")

    def set_with_addresses_data(self) -> None:
        """
        Устанавливает значение self.data, используя кадастровый номер из RequestConfig.cad_number.

        Выполняется перед with_addresses_response

        :return: None
        """
        logger.info('Request on/with-addresses triggered the method set_with_addresses_data')

        self.data: Dict[str, Any] = {
            "filterType": "cadastral",
            "cadNumbers": [RequestConfig.cad_number]
        }
        logger.info(f'Set data with cadNumber: {RequestConfig.cad_number}')

    def set_statement_upload_data(self) -> None:
        """
        Устанавливает значение self.data для загрузки заявления, используя ключи доступа, уникальные идентификаторы
        и другие данные, необходимые для запроса.

        Данные включают информацию о заявителе, объекте недвижимости, кадастровом номере
        из RequestConfig.cad_number. Уникальные идентификаторы генерируются с использованием UUID4.

        Выполняется перед statement_upload_response

        :return: None
        """

        logger.info('Request statement/upload triggered the method set_statement_upload_data')

        self.data: Dict[str, Any] = {
            "title": "Предоставление сведений об объектах недвижимости и (или) их правообладателях",
            # Генерирует уникальные идентификаторы UUID4
            "superPackageGuid": str(uuid.uuid4()),
            "statementGuid": str(uuid.uuid4()),
            "packageGuid": str(uuid.uuid4()),
            "draftGuid": str(uuid.uuid4()),
            "sign": False,
            "dataType": {"code": "object"},
            "purpose": {
                "formType": "EGRNRequest",
                "actionCode": "659511111113",
                "statementType": "558630300000",
                "accessKey": RequestConfig.accessKey,
                "resourceType": "fgisEgrn"
            },
            "agreement": {"dataProcessingAgreement": True},
            "declarantKind": {"code": "declarant"},
            "declarantType": {"code": "person"},
            "deliveryAction": {
                "delivery": "785003000000",
                "linkEmail": RequestConfig.attributes["email"]
            },
            "declarants": [
                {
                    "firstname": RequestConfig.attributes["firstName"],
                    "surname": RequestConfig.attributes["lastName"],
                    "patronymic": RequestConfig.attributes["middleName"],
                    "countryInformation": RequestConfig.attributes["citizenship"],
                    "snils": RequestConfig.attributes["snils"],
                    "email": RequestConfig.attributes["email"],
                    "phoneNumber": RequestConfig.attributes["phone"],
                    "addresses": []
                }
            ],
            "representative": [],
            "attachments": [
                {
                    "documentTypeCode": "008001001000",
                    "documentParentCode": "008001000000",
                    "series": RequestConfig.document["series"],
                    "number": RequestConfig.document["number"],
                    "issueDate": RequestConfig.document["issueDate"],
                    "issuer": RequestConfig.document["issuedBy"],
                    "subjectType": "declarant"
                }
            ],
            "objects": [
                {
                    "objectTypeCode": RequestConfig.element["objType"],
                    "cadastralNumber": RequestConfig.cad_number,
                    "physicalProperties": [
                        {
                            "property": "area",
                            "propertyValue": RequestConfig.element["mainCharacters"][0]["value"],
                            "unittypearea": RequestConfig.element["mainCharacters"][0]["unitCode"]
                        }
                    ]
                }
            ],
            "uptodate": {"uptodateData": True},
            "specialDeclarantKind": {"code": "357039000000"},
            "extractDataRequestType1": "101",
            "actionType": "info"
        }
        logger.info(
            f'SuperPackageGuid: {self.data.get("superPackageGuid", "")}, '
            f'StatementGuid: {self.data.get("statementGuid", "")}, PackageGuid: {self.data.get("packageGuid", "")}, '
            f'DraftGuid: {self.data.get("draftGuid", "")}')
        logger.info(f'AccessKey: {self.data.get("purpose", {}).get("accessKey", "")}')
        logger.info(f'Email: {self.data.get("deliveryAction", {}).get("linkEmail", "")}')
        logger.info(
            f'Declarant first name: {self.data.get("declarants", [{}])[0].get("firstname", "")}, '
            f'last name: {self.data.get("declarants", [{}])[0].get("surname", "")}, '
            f'patronymic: {self.data.get("declarants", [{}])[0].get("patronymic", "")}')
        logger.info(
            f'Document series: {self.data.get("attachments", [{}])[0].get("series", "")}, '
            f'number: {self.data.get("attachments", [{}])[0].get("number", "")}, '
            f'issue date: {self.data.get("attachments", [{}])[0].get("issueDate", "")}')
        logger.info(
            f'ObjectTypeCode: {self.data.get("objects", [{}])[0].get("objectTypeCode", "")}, '
            f'cadastral number: {self.data.get("objects", [{}])[0].get("cadastralNumber", "")}')
        physical_property_value = self.data.get("objects", [{}])[0].get("physicalProperties", [{}])[0].get(
            "propertyValue", "")
        logger.info(f'Physical property area: {physical_property_value}')
        physical_property_unit_type = self.data.get("objects", [{}])[0].get("physicalProperties", [{}])[0].get(
            "unittypearea", "")
        logger.info(f'Physical property unit type: {physical_property_unit_type}')

    def process_statement_upload_response(self, response: requests.Response, retry_count: int=0) -> Optional[Response]:
        """
        Обрабатывает HTTP-ответ на загрузку заявления. В случае ошибки 500 повторяет запрос до 5 раз с паузой в 10 секунд.

        Если после 5 попыток сервер продолжает возвращать статус-код 500, выбрасывается исключение. При успешном запросе
        сохраняет superPackageGuid, accessKey и esiaUserId в атрибуты класса RequestConfig.

        Возвращает новый объект requests.Response, если запрос удался, или None, код изначально был 200.

        Выполняется после statement_upload_response

        :param response: HTTP-ответ от сервера.
        :type response: requests.Response
        :param retry_count: Счётчик попыток повторного запроса в случае ошибки 500 (по умолчанию 0).
        :type retry_count: int
        :return: Возвращает объект requests.Response при успешном запросе, или None.
        :rtype: Optional[requests.Response]
        :raises Exception: Если после 5 попыток ответ по-прежнему содержит статус 500.
        """

        logger.info('Request statement/upload triggered the method process_statement_upload_response',
                    extra={'attempt_number': retry_count + 1})

        if response.status_code == 500:  # Если сервер возвращает код 500, повторяет запрос 5 раз с паузой в 10 секунд
            if retry_count < 5:
                logger.info(
                    f'{response.status_code} Internal Server Error, retrying request. Attempt {retry_count + 1}. '
                    f'Response: {response.text}')
                time.sleep(10)
                new_response: requests.Response = self.session.post(self.url, headers=self.headers, json=self.data)
                # Повторяет обработку ответа после повторного запроса
                return self.process_statement_upload_response(new_response, retry_count + 1)
            else:
                # Если после 5 попыток 500 сохраняется - выбрасывает исключение
                logger.error('Failed to upload statement after 5 attempts due to Internal Server Error (500).',
                             extra={'status_code': response.status_code, 'response_text': response.text})
                raise Exception("Failed to upload statement after 5 attempts due to Internal Server Error (500).")

        # Если запрос успешен, извлекает superPackageGuid, accessKey и esiaUserId
        RequestConfig.superPackageGuid = self.data.get("superPackageGuid", "")
        RequestConfig.accessKey = self.data.get("purpose", {}).get("accessKey", "")
        RequestConfig.esiaUserId = self.session.cookies.get("PC_USER_WAS_AUTHORIZED", "")

        if response.status_code == 200 and retry_count > 0:
            # Если запрос успешен после повторных попыток, возвращает response, заменяющий исходный
            logger.info(f'{response.status_code} Request eventually successful on attempt {retry_count + 1}.')
            return response

    def set_response_finish_data(self) -> None:
        """
        Устанавливает значение self.data для завершения запроса, используя superPackageGuid, esiaUserId, accessKey.

        Выполняется перед response_finish

        :return: None
        """
        logger.info('Request response/finish triggered the method set_response_finish_data')
        self.data: Dict[str, str] = {
            "superPackageGuid": RequestConfig.superPackageGuid,
            "esiaUserId": RequestConfig.esiaUserId,
            "subjectObject": "",
            "packageType": "egrn_with_docs_1",
            "accessKey": RequestConfig.accessKey
        }
        logger.info(f'SuperPackageGuid: {RequestConfig.superPackageGuid}')
        logger.info(f'EsiaUserId: {RequestConfig.esiaUserId}')
        logger.info(f'PackageType: egrn_with_docs_1')
        logger.info(f'AccessKey: {RequestConfig.accessKey}')

    def set_page_response_data(self) -> None:
        """
        Устанавливает значение self.data для запроса, который в ответе вернёт ссылку на скачивание.

        Выполняется перед page_response

        :return: None
        """
        self.data: Dict[str, str] = {
            "requestNumber": "",
            "cadastralNumber": RequestConfig.cad_number,
            "startDate": None,
            "endDate": None
        }

    def get_link_to_download(self, response: requests.Response, retry_count: int=0) -> Optional[requests.Response]:
        """
        Обрабатывает ответ на запрос applications/download и извлекает ссылку на скачивание, если она доступна.

        В случае ошибки 503 запрос повторяется до 5 раз с паузой в 10 секунд. Если после 5 попыток данные не были получены,
        выбрасывается исключение. Если запрос успешен, извлекается ссылка на скачивание, сохраняется в атрибуте
        RequestConfig.download_link и возвращает response.

        Если запрос был с код 200 изначально, возвращает None.

        Выполняется после page_response

        :param response: HTTP-ответ от сервера.
        :type response: requests.Response
        :param retry_count: Счётчик попыток повторного запроса в случае ошибки 503 (по умолчанию 0).
        :type retry_count: int
        :return: Возвращает объект requests.Response при успешном запросе, или None, если запрос не удался.
        :rtype: Optional[requests.Response]
        :raises RuntimeError: Если сервер требует перезагрузить страницу (ключ 'link' найден в ответе).
        :raises requests.exceptions.RequestException: Если после 5 попыток запрос всё ещё не содержит данных.
        """
        logger.info('Request applications/download triggered the method get_link_to_download',
                    extra={'attempt_number': retry_count + 1})
        data: Dict[str, Any] = response.json()
        if 'link' in data: # Если в data есть ключ link, значит сервер требует перезагрузить страницу
            raise RuntimeError(f"Reboot link found: {data['link']}")
        if "content" not in data:  # если content не в data, повторяет запрос 5 раз с паузой в 10 секунд
            if retry_count < 5:
                logger.info(
                    f'{response.status_code} Сontent is not found, retrying request. Attempt {retry_count + 1}. '
                    f'Response: {response.text}')
                time.sleep(10)
                new_response: requests.Response = self.session.post(self.url, headers=self.headers, json=self.data)
                return self.get_link_to_download(new_response, retry_count + 1)
            else:  # Если после 5 попыток content не data - выбрасывает исключение
                logger.error('Failed to retrieve data after 5 attempts due to content is empty.',
                             extra={'status_code': response.status_code, 'response_text': response.text})

                raise (requests.exceptions.RequestException
                       (f"Failed to retrieve data after 5 attempts due to content is empty.{response.text}"))
        # Если в data есть content, а статус "processed", извлекаем id и создаем ссылку на скачивание
        elif len(data["content"]) > 0 and data["content"][0]["statusCode"] == 'processed':
            logger.info(f'Content found: {data["content"]}')
            content_id: int = response.json()["content"][0]["id"]
            RequestConfig.download_link = f'https://lk.rosreestr.ru/account-back/applications/{content_id}/download'
        # Если в data есть content, а статус не "processed", значит, выписка ещё не готова
        elif data["content"][0]["statusCode"] != 'processed':
            logger.info(f'Order not processed yet: {data["content"]}')
            RequestConfig.download_link = None

        # Если в data есть content, но он пустой, значит, выписка не была заказана или заказ не был принят
        elif len(data["content"]) == 0:
            logger.error('Failed to retrieve data due to content is empty.',
                         extra={'status_code': response.status_code, 'response_text': response.text})
            RequestConfig.download_link = None

        # Если запрос успешен после повторных попыток, возвращает response, заменяющий исходный
        if response.status_code == 200 and retry_count > 0:
            return response

    def set_download_response_url(self) -> None:
        """
        Устанавливает значение self.url, используя ссылку на скачивание из RequestConfig.download_link.

        Если download_link не определён, логирует ошибку.

        Выполняется перед download_response

        :return: None
        """
        if RequestConfig.download_link is None:
            logger.error('Download link is None')
        else:
            self.url = RequestConfig.download_link


class GOSSolver:
    # Класс GOSSolver был взят из репозитория https://github.com/warwar-kill.
    # Точные детали его работы неизвестны, но большое спасибо автору. С меня пиво.

    _path = bytes.fromhex(
        "68747470733a2f2f7777772e676f7375736c7567692e72752f5f5f6a7363682f736368656d612e6a736f6e").decode()
    _verifier = bytes.fromhex("5f5f6a7363682f7374617469632f7363726970742e6a73")
    _cache = {}

    @property
    def path(self) -> str:
        return self._path

    def bypass(self, resp: bytes) -> bool:
        return self._verifier not in resp

    @staticmethod
    def time_bucket(a):
        ts = int(time.time())
        return ts - ts % a

    def lookup(self, a, ip) -> Optional[Tuple[int, str, Dict[str, str]]]:
        current = self._cache.get(ip)
        if current is None:
            return None
        next_bucket, _, _ = current
        now_bucket = self.time_bucket(a)
        if next_bucket > now_bucket:
            return current
        del self._cache[ip]
        return None

    def solve(self, ua, resp, *, cache_key: str) -> Tuple[int, Dict[str, str]]:
        a, ip, cn = resp["a"], resp["ip"], resp["cn"]
        bucket = self.time_bucket(a)
        value = f"{ua}:{ip}:{bucket}"

        hasher = md5
        for pos in range(10_000_000):
            response = hasher(f'{value}{pos}'.encode()).hexdigest()
            if response[6:10] == '3fe3':
                cookies = {
                    cn: response.upper(),
                    f"{cn}_2": pos,
                    f"{cn}_3": crc32(value.encode())
                }
                self._cache[cache_key] = (bucket + a, ua, cookies)
                return bucket + a, cookies
        raise ValueError("invalid input")


class CustomSession(requests.Session):
    """
    Класс-наследник requests.Session, изменяет проверку SSL-сертификатов.

    Этот класс отключает проверку SSL-сертификатов для всех запросов, отправляемых через Росреестр и Госуслуги,
    так как эти сервисы не используют корректные сертификаты.

    Methods:
    --------
    request(method: str, url: str, *args, **kwargs) -> requests.Response:
        Переопределяет стандартный метод request, отключая проверку сертификатов.
    """

    def request(self, method: str, url: str, *args, **kwargs) -> requests.Response:
        """
        Выполняет HTTP-запрос, отключая проверку SSL-сертификатов.

        :param method: Метод HTTP-запроса (GET, POST и т.д.).
        :type method: str
        :param url: URL для выполнения запроса.
        :type url: str
        :param args: Дополнительные аргументы для запроса.
        :param kwargs: Дополнительные именованные параметры для запроса.
        :return: Возвращает объект requests.Response.
        :rtype: requests.Response
        """
        kwargs['verify'] = kwargs.get('verify', False)
        return super().request(method, url, *args, **kwargs)

