import logging
import requests
from urllib.parse import urlparse
from packageurl import PackageURL
DepsMemory = [] # для отслеживания обработанных зависимостей

class Dependency:
    def __init__(self, name: str, version: str, depType: list, purl: str, pathToSbom: str):
        self.name = name
        self.version = version
        self.srcLangs = []
        self.source = None
        logging.info(f"Форматирование зависимости: {self.name}, версия {self.version}")

        self.depType = depType
        self.purl = purl
        self.pathToSbom = pathToSbom
        if self not in DepsMemory:
            try:
                self.processPurl(purl)
            except Exception as e:
                logging.exception(f"Ошибка при processPurl для {purl}: {e}")
            DepsMemory.append(self)
        else:
            oldDep = DepsMemory[DepsMemory.index(self)]
            self.srcLangs = oldDep.srcLangs
            self.source = oldDep.source

    def _processDebPkg(self, purlProcessed):
        try:
            logging.info(f"_processDebPkg: {purlProcessed.name}")
            trackerUrl = f"https://tracker.debian.org/pkg/{purlProcessed.name}"
            trackerResponse = requests.get(trackerUrl, timeout=10)
            if trackerResponse.status_code != 200:
                logging.warning(f"Трекер недоступен для {purlProcessed.name}: {trackerResponse.status_code}")
                return ["C"], None
            return ["C"], trackerUrl
        except Exception as e:
            logging.exception(f"Ошибка при обработке Debian пакета {purlProcessed.name}: {e}")
            return ["C"], None

    def _processMVNPkg(self, purlProcessed):
        logging.info(f"_processMVNPkg: {purlProcessed.name} -> ставим Java по умолчанию")
        return ["Java"]

    def _processNugetPkg(self, purlProcessed):
        try:
            langs = []
            pkgSrcUrl = f"https://www.nuget.org/packages/{purlProcessed.name}/{purlProcessed.version}"
            logging.info(f"Запрос NuGet: {pkgSrcUrl}")
            indexResponse = requests.get(pkgSrcUrl, timeout=10)
            if indexResponse.status_code != 200:
                logging.warning(f"Не удалось получить NuGet пакет {purlProcessed.name} -> NUGET check manually")
                return ['NUGET check manually'], pkgSrcUrl

            soup = BeautifulSoup(indexResponse.text, 'html.parser')
            sourceRepoLink = soup.find(attrs={"data-track": "outbound-repository-url"}) \
                or soup.find(attrs={"data-track": "outbound-project-url"}) \
                or soup.find(attrs={"data-track": "outbound-nugetpackageexplorer-url"}) \
                or soup.find(attrs={"data-track": "outbound-manual-download"})

            if not sourceRepoLink or not sourceRepoLink.get('href'):
                logging.info(f"Репозиторий не найден в NuGet -> NUGET check manually")
                return ['NUGET check manually'], pkgSrcUrl

            pkgSrcUrl = sourceRepoLink['href']
            if 'github.com' in pkgSrcUrl:
                cleanContent = self._cleanGitUrl(pkgSrcUrl)
                githubApiUrl = f"https://api.github.com/repos/{cleanContent}/languages"
                headers = {
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {os.getenv('GITHUB_TOKEN')}",
                }
                logging.info(f"GitHub API (NuGet): {githubApiUrl}")
                langsResponse = requests.get(githubApiUrl, headers=headers, timeout=10)
                if langsResponse.status_code == 200:
                    langsJson = langsResponse.json()
                    langs = list(langsJson.keys())
                    if langs:
                        logging.info(f"Определены языки: {langs}")
                        return langs, pkgSrcUrl
                logging.warning(f"Не удалось получить языки из GitHub API -> NUGET check manually")
                return ['NUGET check manually'], pkgSrcUrl

            logging.info("NuGet: репозиторий не GitHub -> NUGET check manually")
            return ['NUGET check manually'], pkgSrcUrl
        except Exception as e:
            logging.exception(f"Ошибка при обработке NuGet пакета {purlProcessed.name}: {e}")
            return ['NUGET check manually'], None

    def _processNpmPkg(self, purlProcessed):
        langs = []
        try:
            if purlProcessed.namespace is not None:
                groupPath = purlProcessed.namespace.replace('.', '/')
                apiPkgUrl = f"https://registry.npmjs.com/{groupPath}/{purlProcessed.name}/{purlProcessed.version}"
                pkgSrcUrl = f"https://www.npmjs.com/package/{groupPath}/{purlProcessed.name}/v/{purlProcessed.version}"
            else:
                apiPkgUrl = f"https://registry.npmjs.com/{purlProcessed.name}/{purlProcessed.version}"
                pkgSrcUrl = f"https://www.npmjs.com/package/{purlProcessed.name}/v/{purlProcessed.version}"

            logging.info(f"Запрос к NPM API: {apiPkgUrl}")
            apiResponse = requests.get(apiPkgUrl, timeout=10)
            logging.info(f"NPM API ответ: {apiResponse.status_code}")

            if apiResponse.status_code != 200:
                logging.warning(f"Невозможно получить информацию о зависимости {purlProcessed.name}, {apiPkgUrl}")
                return ['JavaScript*'], pkgSrcUrl

            content = apiResponse.json()
            if not content.get('repository') or not content['repository'].get('url'):
                logging.info("Репозиторий не указан в package.json -> JavaScript*")
                return ['JavaScript*'], pkgSrcUrl

            cleanContent = self._cleanGitUrl(content['repository']['url'])
            logging.info(f"Очищенный URL репозитория: {cleanContent}")

            if 'github.com' in cleanContent:
                githubApiUrl = f"https://api.github.com/repos/{cleanContent}/languages"
                headers = {
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {os.getenv('GITHUB_TOKEN')}",
                }
                logging.info(f"Запрос к GitHub API: {githubApiUrl}")
                langsResponse = requests.get(githubApiUrl, headers=headers, timeout=10)
                logging.info(f"GitHub API ответ: {langsResponse.status_code}")
                if langsResponse.status_code == 200:
                    langsJson = langsResponse.json()
                    for l in langsJson.keys():
                        langs.append(l)
                    if len(langs) == 0:
                        logging.info("GitHub API вернул пустой список языков -> JavaScript*")
                        return ['JavaScript*'], pkgSrcUrl
                    logging.info(f"Определены языки: {langs}")
                    return langs, pkgSrcUrl
                else:
                    logging.warning("Невозможно получить информацию из GitHub -> JavaScript*")
                    return ['JavaScript*'], pkgSrcUrl

            logging.info("Репозиторий не на GitHub -> JavaScript*")
            return ['JavaScript*'], pkgSrcUrl
        except Exception as e:
            logging.exception(f"Ошибка при обработке npm пакета {purlProcessed.name}: {e}")
            return ['JavaScript*'], pkgSrcUrl

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

    def processPurl(self, purl: str):
        logging.info(f"processPurl: {purl}")
        try:
            p = PackageURL.from_string(purl)
            logging.info(f"PURL parsed: type={p.type}, name={p.name}, namespace={p.namespace}")

            if 'ebp' in purl or 'lanit' in purl:
                logging.info("Внутренний ресурс обнаружен -> ставим дефолтные значения")
                if p.type == "maven":
                    groupPath = p.namespace.replace('.', '/') if p.namespace else p.name
                    self.source = f"https://INNER-RESOURCE/{groupPath}/{p.name}/{p.version}/{p.name}-{p.version}.jar"
                    self.srcLangs = ['Java']
                elif p.type == "pypi":
                    self.srcLangs = ["Python"]
                    self.source = f"https://INNER-RESOURCE/{p.name}/{p.version}/"
                elif p.type == "npm":
                    groupPath = p.namespace.replace('.', '/') if p.namespace else p.name
                    self.source = f"https://INNER-RESOURCE/{groupPath}/{p.name}/v/{p.version}"
                    self.srcLangs = ['JavaScript']
                return

            if p.type == "maven":
                groupPath = p.namespace.replace('.', '/') if p.namespace else p.name
                self.source = f"https://repo1.maven.org/maven2/{groupPath}/{p.name}/{p.version}/{p.name}-{p.version}.jar"
                self.srcLangs = self._processMVNPkg(p)
            elif p.type == "pypi":
                self.srcLangs = ["Python"]
                self.source = f"https://pypi.org/project/{p.name}/{p.version}/"
            elif p.type == "npm":
                self.srcLangs, self.source = self._processNpmPkg(p)
            elif p.type == "deb":
                self.srcLangs, self.source = self._processDebPkg(p)
            elif p.type == "nuget":
                self.srcLangs, self.source = self._processNugetPkg(p)
            else:
                logging.info(f"Необработанный тип purl: {p.type} -> оставляем пустые значения")
        except Exception as e:
            logging.exception(f"Ошибка при обработке PURL ({purl}): {e}")

    def __eq__(self, other):
        if not isinstance(other, Dependency):
            return NotImplemented
        return (self.name, self.version, self.purl) == (other.name, other.version, other.purl)

    def __hash__(self):
        return hash((self.name, self.version, self.purl))


    def processSboms(sbom_dir, report_dir):
        logging.info(f"processSboms: {sbom_dir} -> {report_dir}")
        handler = SbomHandler(sbom_dir)
        for sbomPath in handler.sbomsList:
            try:
                logging.info(f"Обработка SBOM: {sbomPath}")
                sbomContent = handler.readJson(sbomPath)

                if sbomContent is None:
                    logging.warning("SBOM не удалось прочитать или он некорректен -> пропуск")
                    continue

                base = os.path.basename(sbomPath).replace('.json', '')
                excelName = f"{report_dir}/excel/{base}.xlsx"
                odtName = f"{report_dir}/odt/{base}.odt"

                if os.path.exists(excelName) and os.path.exists(odtName):
                    logging.info(f"Отчеты уже существуют ({base}) -> пропуск")
                    continue

                allDependencies = [
                    Dependency(c['name'], c['version'], [], c['purl'], sbomPath)
                    for c in sbomContent.get('components', []) if c.get('type') == 'library'
                ]

                logging.info(f"Собрано внешних зависимостей: {len(allDependencies)}")

                exporter = Exporter(allDependencies)
                exporter.exportToExcel(excelName)
                exporter.exportToOdt(odtName)
            except Exception as e:
                logging.exception(f"Ошибка при обработке файла {sbomPath}: {e}")