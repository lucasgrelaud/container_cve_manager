import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException, ConnectionError
from json import JSONDecodeError


class HarborAPI:
    PAGE_SIZE: int = 10

    auth: HTTPBasicAuth
    base_url: str

    base_image_project_name: str

    def __init__(self):
        self.auth = HTTPBasicAuth(settings.HARBOR_API.get('USERNAME'), settings.HARBOR_API.get('PASSWORD'))
        self.base_url = settings.HARBOR_API.get('API_URL')

        self.base_image_project_name = settings.HARBOR_API.get('BASE_IMAGE_PROJECT_NAME')
        self.test_connection()

    def test_connection(self):
        if self.auth.username is None or self.auth.password is None:
            raise ImproperlyConfigured("Error : no credentials given for the Harbor API")
        if self.base_image_project_name is None:
            raise ImproperlyConfigured("Error : no project name given for Harbor base images")

        url: str = '{0}/health'.format(self.base_url)
        try:
            r = requests.get(url, auth=self.auth)
            if r.status_code != requests.codes.ok:
                raise ImproperlyConfigured("Error while testing the Harbor API configuration.")

        except ConnectionError:
            raise ImproperlyConfigured("Error while connecting on the Harbor API : Check API url.")
        except RequestException:
            raise ImproperlyConfigured("Error while testing the Harbor API configuration.")

    def get_project_list(self) -> dict:
        projects_list: dict = dict()
        next_page_available: bool = True
        current_page: int = 1
        while next_page_available:
            url: str = '{0}/projects?page_size={1}&page={2}'.format(self.base_url, self.PAGE_SIZE, current_page)
            try:
                r = requests.get(url, auth=self.auth)
                if r.status_code != requests.codes.ok:
                    pass
                else:
                    if r.headers.get('link'):
                        if 'next' in r.headers['link']:
                            current_page = current_page + 1
                        else:
                            next_page_available = False
                    else:
                        next_page_available = False
                    for project in r.json():
                        projects_list[project['name']] = project['project_id']
            except RequestException:
                pass
            except JSONDecodeError:
                pass

        return projects_list

    def get_image_list(self, project_name: str) -> dict:
        base_image_list: list = list()
        next_page_available: bool = True
        current_page: int = 1
        while next_page_available:
            url: str = '{0}/projects/{1}/repositories?page_size={2}&page={3}'. \
                format(self.base_url, project_name, self.PAGE_SIZE, current_page)
            try:
                r = requests.get(url, auth=self.auth)
                if r.status_code != requests.codes.ok:
                    pass
                else:
                    if r.headers.get('link'):
                        if 'next' in r.headers['link']:
                            current_page = current_page + 1
                        else:
                            next_page_available = False
                    else:
                        next_page_available = False
                    for image in r.json():
                        base_image_list.append(image.get('name'))
            except RequestException:
                pass
            except JSONDecodeError:
                pass

        return {'image': base_image_list}

    def get_base_image_list(self) -> dict:
        return self.get_image_list(self.base_image_project_name)

    def get_image_tag(self, project_name:str, image_name: str) -> dict:
        artifact_list: list = list()

        next_page_available: bool = True
        current_page: int = 1
        while next_page_available:
            url: str = '{0}/projects/{1}/repositories/{2}/artifacts?page_size={3}&with_tag=true&page={4}'. \
                format(self.base_url, project_name, image_name, self.PAGE_SIZE, current_page)
            try:
                r = requests.get(url, auth=self.auth)
                if r.status_code != requests.codes.ok:
                    pass
                else:
                    if r.headers.get('link'):
                        if 'next' in r.headers['link']:
                            current_page = current_page + 1
                        else:
                            next_page_available = False
                    else:
                        next_page_available = False
                    for artifact in r.json():
                        for tag in artifact.get('tags'):
                            artifact_list.append(tag.get('name'))
            except RequestException:
                pass
            except JSONDecodeError:
                pass

        return {'tag': artifact_list}

    def get_base_image_tag(self, image_name: str) -> dict:
        return self.get_image_tag(self.base_image_project_name, image_name)

    def get_image_vulnerabilities(self, project_name: str, image_name: str, image_tag: str) -> list:
        addition_list: list = list()

        next_page_available: bool = True
        current_page: int = 1
        while next_page_available:
            url: str = '{0}/projects/{1}/repositories/{2}/artifacts/{3}/additions/vulnerabilities'.\
                format(self.base_url, project_name, image_name, image_tag)
            try:
                r = requests.get(url, auth=self.auth)
                if r.status_code != requests.codes.ok:
                    pass
                else:
                    if r.headers.get('link'):
                        if 'next' in r.headers['link']:
                            current_page = current_page + 1
                        else:
                            next_page_available = False
                    else:
                        next_page_available = False
                    for artifact in r.json().values():

                        if artifact.get('vulnerabilities'):
                            addition_list.extend(artifact.get('vulnerabilities'))
            except RequestException:
                pass
            except JSONDecodeError:
                pass

        return addition_list

    def get_base_image_vulnerabilities(self, image_name: str, image_tag: str):
        return self.get_image_vulnerabilities(self.base_image_project_name, image_name, image_tag)