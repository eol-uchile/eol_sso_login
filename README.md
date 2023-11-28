# EOL SSO Login
![https://github.com/eol-uchile/eol_sso_login/actions](https://github.com/eol-uchile/eol_sso_login/workflows/Python%20application/badge.svg) 

# Install App

    docker-compose exec lms pip install -e /openedx/requirements/eol_sso_login
    docker-compose exec cms pip install -e /openedx/requirements/eol_sso_login
    docker-compose exec lms python manage.py lms --settings=prod.production makemigrations eol_sso_login
    docker-compose exec lms python manage.py lms --settings=prod.production migrate eol_sso_login

## Translation

**Install**

    docker run -it --rm -w /code -v $(pwd):/code python:3.8 bash
    pip install -r requirements.txt
    make create_translations_catalogs
    add your translation in .po files

**Compile**

    docker run -it --rm -w /code -v $(pwd):/code python:3.8 bash
    pip install -r requirements.txt
    make compile_translations

**Update**

    docker run -it --rm -w /code -v $(pwd):/code python:3.8 bash
    pip install -r requirements.txt
    make update_translations



## TESTS
**Prepare tests:**

    > cd .github/
    > docker-compose run lms /openedx/requirements/eol_sso_login/.github/test.sh
