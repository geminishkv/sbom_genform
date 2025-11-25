from urllib.parse import urlparse, urlunparse

def clean_git_url(url):
def _cleanGitUrl(self, url):
        logging.debug(f"Очистка git URL: {url}")
        if url.endswith('.git'):
            url = url[:-4]

        if url.startswith('git@'):
            url = url.split(':')[-1]

        if url.startswith('git+ssh://git@'):
            url = url.split('git@github.com/')[-1]

        parsed_url = urlparse(url)

        if parsed_url.scheme == 'git+':
            parsed_url = parsed_url._replace(scheme='https')

        if parsed_url.netloc.startswith('www.'):
            parsed_url = parsed_url._replace(netloc=parsed_url.netloc[4:])

        if parsed_url.netloc == 'github.com':
            cleaned_url = parsed_url.path.lstrip('/')
        else:
            cleaned_url = urlunparse(parsed_url)

        logging.debug(f"Очищенный git URL: {cleaned_url}")
        return cleaned_url
    return cleaned_url