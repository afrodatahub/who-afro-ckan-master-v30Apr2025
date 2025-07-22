FROM fjelltopp/ckan:base

USER root

RUN rm -rf /usr/lib/ckan/*

COPY ./Pip* /usr/lib/ckan/
COPY ./ckan /usr/lib/ckan/ckan
COPY ./ckanext-who-afro /usr/lib/ckan/ckanext-who-afro
RUN rm -rf /usr/lib/ckan/ckan/ckan/pastertemplates/template/ckanext_+project_shortname+.egg-info

RUN cd /usr/lib/ckan/ && mkdir .venv && pipenv sync && \
    ln -s .venv venv

RUN pipenv install packaging --skip-lock

COPY --chown=ckan:ckan ./ /usr/lib/ckan/

ENV PATH=${CKAN_VENV}/bin:${PATH}

RUN cd /usr/lib/ckan/ckanext-who-afro/ckanext/who_afro/react/ && \
    yarn install && \
    yarn build

RUN pip install packaging
ENTRYPOINT ["/usr/lib/ckan/ckan-entrypoint.sh"]

EXPOSE 5000
CMD ${CKAN_VENV}/bin/uwsgi --ini-paste ${CKAN_CONFIG}/ckan-uwsgi.ini
