import requests
import enum


def post_request(bb, url: str, api_key: str, files: dict) -> requests.Response:
    return _make_request(bb, url, Method.POST, api_key, files=files, json={}, params={})


def put_request(bb, url: str, api_key: str, json: dict) -> requests.Response:
    return _make_request(bb, url, Method.PUT, api_key, files={}, json=json, params={})


def get_request(bb, url: str, api_key: str, params: dict = None) -> requests.Response:
    return _make_request(bb, url, Method.GET, api_key, files={}, json={}, params=params)


class Method(enum.Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"


def _make_request(bb, url: str, method: Method, api_key: str, files: dict, json: dict,
                  params: dict) -> requests.Response:
    headers = {"X-API-Key": api_key}
    log_error_string = f"Failed to {method} on Dependency Track server at {url}. {files.keys() = }, {json = }, {params = }. "

    method_dict = {
        Method.GET: requests.get,
        Method.POST: requests.post,
        Method.PUT: requests.put,
    }

    try:
        response = method_dict[method](url, headers=headers, files=files, json=json, params=params)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        # for GET request 404 might be expected, so not an error
        log_function = lambda x: bb.debug(2, x) if method == Method.GET else bb.error

        log_function(log_error_string + f"[HTTP Error] {e}")
        log_function(f"Response: {e.response.status_code} -> {e.response.reason}")
        try:
            log_function(f"Response: {e.response.json()}")
        except ValueError:
            pass

        return e.response
    except requests.exceptions.RequestException as e:
        bb.error(log_error_string + f"[Error] {e}")
        return e.response
    else:
        bb.debug(2, f"Successful {method} to {url}. Response: {response.json()}")

    return response
