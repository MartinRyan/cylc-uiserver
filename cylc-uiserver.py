#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# Copyright (C) 2019 NIWA & British Crown (Met Office) & Contributors.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import absolute_import

import argparse
import asyncio
import json
import logging
import os.path
import signal
import sys
from logging import Formatter, StreamHandler
from logging.config import dictConfig
from urllib.parse import quote, urlencode

from graphene_tornado.schema import schema
from graphene_tornado.tornado_graphql_handler import TornadoGraphQLHandler
from handlers import CylcScanHandler
from services.auth import HubAuthenticated
from services.utils import url_path_join
from tornado import ioloop, log
from tornado.httpclient import AsyncHTTPClient
import tornado.options
from tornado.options import define, options, parse_command_line
from tornado.web import (Application, RequestHandler, StaticFileHandler,
                         authenticated)

define('port', default=8888, help='run port')
define('static', default='cylc-web/', type=str, help='static files path')
define('prefix', type=str, help='jupyterhub-service-prefix')
define('usertoken',type=str, help='jupyterhub user authtoken')
define('hubtoken', type=str, help='jupyterhub api token', metavar='hubtoken')
define('hub_api_url', help='jupyterhub api url', metavar='hub_api_url')
define('hub_base_url', type=str, help='base url - usually /user/username', metavar='hub_base_url')
define('hub_login_url', type=str, help='jupyterhub login url', metavar='hub_login_url')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class BaseHandler(RequestHandler):

    def get_current_user(self):
        logger.info(f' get_current_user {self.current_user}')
        logger.info(f' logger get_current_user {self.current_user}')
        return self.current_user

    async def prepare(self):
        # get_current_user cannot be a co-routine so set here in prepare
        usertoken = self._usertoken
        hub_api_url = self._hub_api_url
        if usertoken and hub_api_url:
            self.current_user = await self.get_user_auth(usertoken)
            logger.info(f' self.current_user {self.current_user}')
        else:
            self.redirect_to_login()

    async def get_user_auth(self, token):
        """Check if the user is authenticated with JupyterHub if the hub
        API endpoint and token are configured.
        Redirect unauthenticated requests to the JupyterHub login page.
        """
        usertoken = token
        logger.info(f' token {usertoken}')
        logger.info(f' self._hub_api_url {self._hub_api_url}')
        logger.info(f' self._hub_login_url {self._hub_login_url}')

        def redirect_to_login():
            self.redirect(url_path_join(self._hub_login_url) +
                          '?' + urlencode({'next': self.request.path}))

        try:
            #  if hub returns a success code, user is known
            async_http_client = AsyncHTTPClient()
            response = await async_http_client.fetch(
                url_path_join(self._hub_api_url,
                              'authorizations/token',
                              usertoken,
                              quote(usertoken, safe='')),
                headers={
                    'Authorization': 'token ' + usertoken
                }
            )
            logger.info(f' hub auth response {response.body}')
        except async_http_client.HTTPError as ex:
            logging.error(f' ex.response.code > {ex.response.code}')
            logging.error(f' error {ex.object}')
            if ex.response.code == 404:
                # hub does not recognize the cookie == not authenticated
                logging.error(f' hub does not recognize the token 404')
                raise asyncio.Return(redirect_to_login())
            # let all other errors surface: they're unexpected
            raise ex
        else:
            logger.info(f' hub auth response {response.body}')
            # self.user = response.json()
            return response.body


class MainHandler(BaseHandler, HubAuthenticated, RequestHandler):

    # hub_users = {'jupyter', 'martin'}
    # hub_groups = {'jupyter'}
    # allow_admin = True

    def initialize(self, path):
        self._static = path
        logger.info(f'initialize path: {self._static}')

    # @authenticated
    def get(self):
        """Render the UI prototype."""
        logger.info(f'MainHandler')
        user_model = self.get_current_user()
        if user_model:
            logger.info(f' user_model{user_model}')
            index = os.path.join(self._static, "index.html")
            self.write(open(index).read())
        else:
            self.redirect(url_path_join(self._hub_login_url) +
                          '?' + urlencode({'next': self.request.path}))


class UserProfileHandler(BaseHandler, HubAuthenticated, RequestHandler):

    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "x-requested-with")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.set_header("Content-Type", 'application/json')

    # @authenticated
    def get(self):
        logger.info(f'UserProfileHandler')
        user_model = self.get_current_user()
        if user_model:
            logger.info(f' usermodel => {user_model}')
            self.write(json.dumps(user_model, indent=1, sort_keys=True))
        else:
            self.redirect(url_path_join(self._hub_login_url) +
                          '?' + urlencode({'next': self.request.path}))


class Application(Application):
    is_closing = False

    def signal_handler(self, signum, frame):
        logger.info('exiting...')
        self.is_closing = True

    def try_exit(self):
        if self.is_closing:
            ioloop.IOLoop.instance().stop()
            logger.info('exit success')


class CylcUIServer(object):

    def __init__(self, port, static, jhub_service_prefix, usertoken,
                 hubtoken, hub_api_url, hub_base_url, hub_login_url):
        self._port = int(port)
        self._static = str(static)
        self._prefix = str(jhub_service_prefix)
        self._usertoken = usertoken
        self._hubtoken = hubtoken
        self._hub_api_url = hub_api_url
        self._hub_base_url = hub_base_url
        self._hub_login_url = hub_login_url
        if os.path.isabs(static):
            self._static = static
        else:
            script_dir = os.path.dirname(__file__)
            self._static = os.path.abspath(os.path.join(
                script_dir, static))
        logger.info(f' Cylc UI Server running on port {self._port}')
        logging.info(f' Cylc UI Server running on port {self._port}')
        logger.info(f' serving static files from: {self._static}')
        logger.info(f' self._prefix ==>> {self._prefix}')
        logger.info(f' self._usertoken ==>> {self._usertoken}')
        logger.info(f' self._hubtoken ==>> {self._hubtoken}')
        logger.info(f' self._hub_api_url ==>> {self._hub_api_url}')
        logger.info(f' self._hub_base_url ==>> {self._hub_base_url}')
        logger.info(f' self._hub_login_url ==>> {self._hub_login_url}')
        logger.info(f' JupyterHub Service Prefix: {self._prefix}')
        logger.info(f'options.prefix init() {options.prefix}')
        logger.info(options.prefix)
        

    def _make_app(self):
        return Application(
            static_path=self._static,
            debug=True,
            handlers=[
                (rf'{self._prefix}(.*.(css|js))',
                 StaticFileHandler, {'path': self._static}),
                (rf'{self._prefix}((fonts|img)/.*)',
                 StaticFileHandler, {'path': self._static}),
                (rf'{self._prefix}(favicon.png)',
                 StaticFileHandler, {'path': self._static}),
                (r'/(.*.(css|js))', StaticFileHandler,
                 {'path': self._static}),
                (r'/((fonts|img)/.*)', StaticFileHandler,
                 {'path': self._static}),
                (r'/(favicon.png)', StaticFileHandler,
                 {'path': self._static}),

                (self._prefix, BaseHandler, {'path': self._static}),
                (url_path_join(self._prefix, 'userprofile'),
                    UserProfileHandler),
                (url_path_join(self._prefix, 'suites'), CylcScanHandler),
                (self._prefix, MainHandler, {'path': self._static}),

                # graphql
                (url_path_join(self._prefix, '/graphql'),
                 TornadoGraphQLHandler, dict(graphiql=True, schema=schema)),
                (url_path_join(self._prefix, '/graphql/batch'),
                    TornadoGraphQLHandler, dict(graphiql=True, schema=schema,
                                                batch=True)),
                (url_path_join(self._prefix, '/graphql/graphiql'),
                 TornadoGraphQLHandler, dict(graphiql=True, schema=schema)),
            ],
            cookie_secret='cylc-secret-cookie'
        )

    def start(self):
        logger.info('starting cylc ui')
        app = self._make_app()
        signal.signal(signal.SIGINT, app.signal_handler)
        app.listen(self._port)
        ioloop.PeriodicCallback(app.try_exit, 100).start()
        try:
            ioloop.IOLoop.current().start()
        except KeyboardInterrupt:
            ioloop.IOLoop.instance().stop()


def main():
    parser = argparse.ArgumentParser(description='Start Cylc UI')
    parser.add_argument('--port', action='store', dest='port', type=int,
                        default=8888)
    parser.add_argument('--static', action='store', dest='static')
    parser.add_argument('--prefix', action='store', dest='prefix')
    parser.add_argument('--usertoken', action='store', dest='usertoken')
    parser.add_argument('--hubtoken', action='store', dest='hubtoken')
    parser.add_argument('--hub_api_url', action='store', dest='hub_api_url')
    parser.add_argument('--hub_base_url', action='store', dest='hub_base_url')
    parser.add_argument('--hub_login_url', action='store',
                        dest='hub_login_url')
    args = parser.parse_args()
    logger.info(f'jupyterhub_service_prefix {args.prefix}')
    ui_server = CylcUIServer(
        port=args.port, static=args.static,
        jhub_service_prefix=args.prefix,
        usertoken=args.usertoken, hubtoken=args.hubtoken,
        hub_api_url=args.hub_api_url,
        hub_base_url=args.hub_base_url,
        hub_login_url=args.hub_login_url
        )
    ui_server.start()

# def main():

#     # parser = argparse.ArgumentParser(description='Start Cylc UI')
#     # parser.add_argument('--port', action='store', dest='port', type=int,
#     #                     default=8888)
#     # parser.add_argument('--static', action='store', dest='static')
#     # parser.add_argument('--prefix', action='store', dest='prefix')
#     # parser.add_argument('--usertoken', action='store', dest='usertoken')
#     # parser.add_argument('--hubtoken', action='store', dest='hubtoken')
#     # parser.add_argument('--hub_api_url', action='store', dest='hub_api_url')
#     # parser.add_argument('--hub_base_url', action='store', dest='hub_base_url')
#     # parser.add_argument('--hub_login_url', action='store',
#     #                     dest='hub_login_url')
#     # args = parser.parse_args()
#     options.parse_command_line()
#     logger.info(f'tornado.options.prefix main() {options.prefix}')
#     logger.info(f'args.authtoken main() {args.authtoken}')
#     logger.info(f'args.port main() {args.port}')
#     ui_server = CylcUIServer(
#         port=options.port, static=options.static,
#         jhub_service_prefix=options.prefix,
#         usertoken=options.usertoken, hubtoken=options.hubtoken,
#         hub_api_url=options.hub_api_url,
#         hub_base_url=options.hub_base_url,
#         hub_login_url=options.hub_login_url
#         )
#     ui_server.start()


def init_logging(access_to_stdout=False):
    if access_to_stdout:
        # access_log = logging.getLogger('tornado.access')
        # access_log.propagate = False
        # make sure access log is enabled even if error level is WARNING|ERROR
        # access_log.setLevel(logger.info)
        # stdout_handler = StreamHandler(sys.stdout)
        # access_log.addHandler(stdout_handler)
        # logger.info('logger init ===>>>>>')
        logger.setLevel(logging.DEBUG)
        # handler = logging.FileHandler('test.log')
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        formatter = Formatter('%(levelname)s %(asctime)s path:%(pathname)s lineno:%(lineno)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.info('logger init ===>>>>>')



def bootstrap():
    options.parse_command_line()
    # log.enable_pretty_logging()
    init_logging(True)  # set access_to_stdout to True


if __name__ == '__main__':
    bootstrap()
    # logger.info(f'name main port ===>>>>> {options.port}')
    # logger.info(f'name main prefix ===>>>>> {options.prefix}')
    main()


__all__ = ['BaseHandler',
           'main',
           'MainHandler',
           'UserProfileHandler',
           'Application',
           'CylcUIServer',
           ]
