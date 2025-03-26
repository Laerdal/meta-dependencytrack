import requests


def post_request(bb, url: str, api_key: str, files: dict) -> None:
    headers = {"X-API-Key": api_key}
    log_error_string = f"Failed to post to Dependency Track server at {url}, {files.keys() = }. "

    try:
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        bb.error(log_error_string + f"[HTTP Error] {e}")
        bb.error(f"Response: {response.status_code} -> {response.reason}")
        try:
            bb.error(f"Response: {response.json()}")
        except ValueError:
            pass
    except requests.exceptions.RequestException as e:
        bb.error(log_error_string + f"[Error] {e}")
    else:
        bb.debug(2, f"File successfully uploaded to {url}. Response: {response.json()}")


def get_request(bb, url: str, api_key: str, files: dict = None, params: dict = None) -> dict | int | None:
    headers = {"X-API-Key": api_key}
    log_error_string = f"Failed to get from Dependency Track server at {url}, {files.keys() = }, {params = }. "

    try:
        response = requests.get(url, headers=headers, files=files, params=params)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        # for some get requests a 404 is expected, so it is not the error
        bb.debug(log_error_string + f"[HTTP Error] {e}")
        bb.debug(f"Response: {response.status_code} -> {response.reason}")
        try:
            bb.debug(f"Response: {response.json()}")
        except ValueError:
            pass

        return e.response.status_code
    except requests.exceptions.RequestException as e:
        bb.error(log_error_string + f"[Error] {e}")
        return None
    else:
        return response.json()
