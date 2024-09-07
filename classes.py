import json
import uuid
import pyotp
import requests
import time
from hashlib import md5
from zlib import crc32
from typing import Optional, Tuple, Dict
import logging

from credentials import totp_secret

logger = logging.getLogger(__name__)


class RequestConfig:
    # Нужен для описания конфигурации запросов. Он хранит параметры запроса: URL, метод (GET и POST), заголовки,
    # и позволяет задавать действия, которые нужно выполнить перед и после отправки запроса.

    def __init__(self, url: str = None, method: str = 'GET', headers: dict = None, data: dict = None,
                 allow_redirects: bool = True, use_proxies: bool = True,
                 before_request_method: str = None, after_request_method: str = None, solver=None):
        self.url = url
        self.method = method
        self.headers = headers if headers else {}
        self.data = data
        self.allow_redirects = allow_redirects  # Определяет, будут ли автоматически обрабатываться редиректы
        self.use_proxies = use_proxies
        self.before_request_method = before_request_method  # Метод, который будет выполнен перед отправкой запроса
        self.after_request_method = after_request_method  # Метод, который будет выполнен после получения ответа
        self.session = None  # Сессия, используемая для выполнения запроса, инициализируется позже
        # solver используется для обхода проверки на ботов
        # Он принимает параметры из файла schema.json и создаёт куки на их основе
        self.solver = solver

    def execute(self, session: requests.Session):
        # Метод для выполнения запроса с параметрами объекта
        # Если after_request_method возвращает новый response, то он и будет возвращён.
        # Принимает:
        # - session: объект requests.Session
        # Возвращает:
        # - response: объект requests.Response

        logger.info(f'Executing {self.method} request to {self.url}')

        self.session = session  # Сохраняет текущую сессию для использования в других методах

        if self.before_request_method:
            # Если указан метод, который должен выполняться перед запросом,
            # получает ссылку на этот метод и вызывает его, если он существует и может быть вызван.
            method_to_call = getattr(self, self.before_request_method, None)
            if callable(method_to_call):
                method_to_call()  # Вызывает метод для подготовки данных перед выполнением запроса

        proxies = session.proxies if self.use_proxies else {"http": "", "https": ""}
        # Если флаг self.use_proxies True (по умолчанию), используется прокси из сессии.
        # Если False, прокси не используется.

        if self.method.upper() == 'GET':
            # Выполняет GET запрос с указанными параметрами.
            response = session.get(self.url, headers=self.headers, allow_redirects=self.allow_redirects,
                                   proxies=proxies)
        elif self.method.upper() == 'POST':
            # Выполняет POST запрос с указанными параметрами и данными.
            response = session.post(self.url, headers=self.headers, json=self.data,
                                    allow_redirects=self.allow_redirects, proxies=proxies)
        else:
            # Выбрасывает исключение, если метод не поддерживается.
            raise ValueError(f"Unsupported method: {self.method}")

        if self.after_request_method:
            # Если указан метод для обработки ответа, вызывает его.
            method_to_call = getattr(self, self.after_request_method, None)
            if callable(method_to_call):
                new_response = method_to_call(response)
                # Если метод возвращает новый ответ, то возвращает его.
                if new_response:
                    logger.info(f'Received new response from after request method: {self.after_request_method}')
                    return new_response

        return response

    url_from_location = None  # Заполняется в методе extract_url_from_headers
    url_from_redirect_url = None  # Заполняется в методе extract_redirect_url
    document = None  # Заполняется в методе process_info_response
    cad_number = None  # Заполняется в main
    element = None  # Заполняется в методе process_info_response
    attributes = None  # Заполняется в методе process_info_response
    esiaUserId = None  # Заполняется в методе process_statement_upload_response
    accessKey = None  # Заполняется в методе extract_access_key
    superPackageGuid = None  # Заполняется в методе process_statement_upload_response

    def extract_url_from_headers(self, response):
        # Извлекает URL из заголовка ответа Location и сохраняет его в url_from_location.
        logger.info('Request auth/login triggered the method extract_url_from_headers')
        RequestConfig.url_from_location = response.headers.get('Location', '')

    def set_url_from_login_redirect(self):
        # Устанавливает self.url, используя значение url_from_location.
        logger.info('Request client_secret triggered the method set_url_from_login_redirect')
        self.url = RequestConfig.url_from_location

    def handle_schema_response(self, response):
        # Обрабатывает JSON-ответ, решает задачу проверки на ботов и устанавливает cookies
        logger.info('Request __jsch/schema.json triggered the method handle_schema_response')
        schema_response_content = response.content
        try:
            # Пытается распарсить содержимое ответа как JSON.
            response_data = json.loads(schema_response_content)
            user_agent = self.session.headers.get('User-Agent', 'Mozilla/5.0')
            cache_key = response_data["ip"]
            logger.info('Successfully parsed JSON from schema response')
        except json.decoder.JSONDecodeError:
            # Если распарсить не удаётся, значит, вместо JSON содержится HTML с запросом на ввод капчи
            raise Exception("Captcha!")

        logger.info('Solving challenge using solver')
        # Использует solver для решения задачи, связанной с проверкой на ботов.
        bucket_time, generated_cookies = self.solver.solve(user_agent, response_data, cache_key=cache_key)

        # Преобразует все значения в cookies в строковый формат
        for key in generated_cookies:
            generated_cookies[key] = str(generated_cookies[key])

        # Устанавливает сгенерированные cookies для сессии
        for key, value in generated_cookies.items():
            self.session.cookies.set(key, value, domain='esia.gosuslugi.ru')

    def set_pixel_url(self):
        # Устанавливает URL для пикселя, используя значение cookie 'fhp'.
        logger.info('Request empty.gif triggered the method set_pixel_url')
        fhp_value = self.session.cookies.get('fhp')
        self.url = f'https://cbn.gosuslugi.ru/api/v2/pixel/32abbcac-ebe3-45f6-8d39-2732576bbfed/{fhp_value}/empty.gif'

    def cookies_rename(self, response=None):
        # Переименовывает cookies 'gs-tp-id' и 'gs-tp-pid' в 'gs-id' и 'gs-pid' соответственно.
        logger.info('Request empty.gif triggered the method cookies_rename')
        if 'gs-tp-id' in self.session.cookies:
            self.session.cookies.set('gs-id', self.session.cookies.pop('gs-tp-id'), domain='.esia.gosuslugi.ru')

        if 'gs-tp-pid' in self.session.cookies:
            self.session.cookies.set('gs-pid', self.session.cookies.pop('gs-tp-pid'), domain='.esia.gosuslugi.ru')

    def set_totp_url(self):
        # Устанавливает URL для проверки TOTP-кода, сгенерированного pyotp.
        logger.info('Request totp/verify triggered the method set_totp_url')
        totp_code = pyotp.TOTP(totp_secret, digits=6, digest='sha1', interval=30).now()
        logger.info(f'Generated TOTP code: {totp_code}')
        self.url = f'https://esia.gosuslugi.ru/aas/oauth2/api/login/totp/verify?code={totp_code}'

    def extract_redirect_url(self, response):
        # Извлекает URL для редиректа из JSON-ответа и сохраняет его в url_from_redirect_url
        logger.info('Request totp/verify triggered the method extract_redirect_url')
        totp_response_json = response.json()
        RequestConfig.url_from_redirect_url = totp_response_json.get('redirect_url', '')

    def set_auth_process_url(self):
        # Устанавливает self.url, используя значение url_from_redirect_url.
        logger.info('Request auth/process triggered the method set_auth_process_url')
        self.url = RequestConfig.url_from_redirect_url

    def process_roles_response(self, response):
        # Извлекает oid из ответа и устанавливает куки
        logger.info('Request profile/roles triggered the method process_roles_response')
        if response.status_code == 200:
            # Если статус ответа 200, парсит JSON-ответ
            logger.info('Received roles response with status 200')
            response_json = response.json()

            # Проверяет, авторизован ли пользователь. Если 'logged' == False, то извлекает oid
            if not response_json.get('logged', True):
                oid = response_json['roles'][0]['oid']

                # Устанавливает cookie 'PC_USER_WAS_AUTHORIZED' из oid
                self.session.cookies.set('PC_USER_WAS_AUTHORIZED', str(oid), domain='lk.rosreestr.ru')

    def set_oid_url(self):
        # Устанавливает self.url, используя значение oid из cookie 'PC_USER_WAS_AUTHORIZED'
        logger.info('Request profile/info?oid triggered the method set_oid_url')
        oid = self.session.cookies.get('PC_USER_WAS_AUTHORIZED')
        self.url = f'https://lk.rosreestr.ru/account-back/profile/info?oid={oid}'

    def process_info_response(self, response):
        # Обрабатывает JSON-ответ и сохраняет данные в attributes и document
        info_data = response.json()
        RequestConfig.attributes = info_data.get("attributesOauth", {})
        RequestConfig.document = RequestConfig.attributes.get("documents", {}).get("elements", [None])[0]

    def set_on_response_data(self):
        # Устанавливает self.data, кадастровый номер из cad_number, который задаётся в main
        self.data = {
            "filterType": "cadastral",
            "cadNumbers": [RequestConfig.cad_number]
        }
        logger.info(f'Set data with cadNumber: {RequestConfig.cad_number}')

    def process_on_response(self, response, retry_count=0):
        # Обрабатывает ответ на запрос account-back/on. Повторяет запрос до 5 раз в случае ошибки 503
        logger.info('Request account-back/on triggered the method process_on_response',
                    extra={'attempt_number': retry_count + 1})

        if response.status_code == 503:  # При статусе 503 повторяет запрос до 5 раз с паузой в 10 секунд
            if retry_count < 5:
                logger.info(
                    f'{response.status_code} Service Unavailable, retrying request. Attempt {retry_count + 1}. '
                    f'Response: {response.text}')
                time.sleep(10)
                new_response = self.session.get(self.url, headers=self.headers)
                return self.process_on_response(new_response, retry_count + 1)
            else:  # Если после 5 попыток статус 503 сохраняется, выбрасывает исключение
                logger.error('Failed to retrieve data after 5 attempts due to Service Unavailable.',
                             extra={'status_code': response.status_code, 'response_text': response.text})
                raise Exception("Failed to retrieve data after 5 attempts due to Service Unavailable.")
        # Если запрос успешен, извлекает первый элемент из "elements" и сохраняет его в RequestConfig.element
        account_back_on_data = response.json()
        RequestConfig.element = account_back_on_data.get("elements", [None])[0]

        # Если запрос успешен после повторных попыток, возвращает response, заменяющий исходный
        if response.status_code == 200 and retry_count > 0:
            logger.info(f'{response.status_code} Request eventually successful on attempt {retry_count + 1}.')
            return response

    def set_track_png_url(self):
        # Устанавливает self.url для запроса open-card, используя кадастровый номер из RequestConfig.cad_number.
        logger.info('Request open-card triggered the method set_track_png_url')
        self.url = f'https://lk.rosreestr.ru/track.png?a=open-card&s=on&o={RequestConfig.cad_number}&f=search&c='

    def extract_access_key(self, response):
        # Извлекает accessKey из JSON-ответа и сохраняет его в RequestConfig.accessKey
        logger.info('Request account-back/access-key triggered the method extract_access_key')
        RequestConfig.accessKey = response.json().get("guid", "")

    def set_with_addresses_data(self):
        # Устанавливает self.data, кадастровый номер из cad_number, который задаётся в main
        logger.info('Request on/with-addresses triggered the method set_with_addresses_data')

        self.data = {
            "filterType": "cadastral",
            "cadNumbers": [RequestConfig.cad_number]
        }
        logger.info(f'Set data with cadNumber: {RequestConfig.cad_number}')

    def set_statement_upload_data(self):
        # Устанавливает self.data для загрузки заявления, включая accessKey, superPackageGuid, esiaUserId и другие
        # параметры, необходимые для запроса. Данные берутся из соответствующих атрибутов RequestConfig.

        logger.info('Request statement/upload triggered the method set_statement_upload_data')

        self.data = {
            "title": "Предоставление сведений об объектах недвижимости и (или) их правообладателях",
            # Генерирует уникальные идентификаторы с использованием версии 4 UUID
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

    def process_statement_upload_response(self, response, retry_count=0):
        # Обрабатывает ответ на загрузку заявления. При коде 500 повторяет запрос до 5 раз. Если запрос успешен,
        # сохраняет superPackageGuid, accessKey и esiaUserId в атрибуты класса.

        logger.info('Request statement/upload triggered the method process_statement_upload_response',
                    extra={'attempt_number': retry_count + 1})

        if response.status_code == 500:  # Если сервер возвращает код 500, повторяет запрос 5 раз с паузой в 10 секунд
            if retry_count < 5:
                logger.info(
                    f'{response.status_code} Internal Server Error, retrying request. Attempt {retry_count + 1}. '
                    f'Response: {response.text}')
                time.sleep(10)
                new_response = self.session.post(self.url, headers=self.headers, json=self.data)
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

    def set_response_finish_data(self):
        # Устанавливает self.data для завершения запроса, включая superPackageGuid, esiaUserId, accessKey и тип пакета.
        logger.info('Request response/finish triggered the method set_response_finish_data')
        self.data = {
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
    # Меняет requests.Session, чтобы не проверялись сертификаты, потому что, у росреестра и госуслуг их нет
    def request(self, method, url, *args, **kwargs):
        kwargs['verify'] = kwargs.get('verify', False)
        return super().request(method, url, *args, **kwargs)
