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
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import absolute_import

import argparse
import asyncio
import json
import logging
import os.path
import signal
from urllib.parse import quote, urlencode

from graphene_tornado.schema import schema
from graphene_tornado.tornado_graphql_handler import TornadoGraphQLHandler
from tornado import httpclient, ioloop, log, web
from tornado.httpclient import AsyncHTTPClient
from tornado.options import define

from handlers import CylcScanHandler
from services.auth import (HubAuth, HubAuthenticated, HubOAuthCallbackHandler,
                           HubOAuthenticated)
from services.utils import url_path_join

define('port', default=8888, type=int, help='run port')
define('static', default='../cylc-web/', type=str, help='static files path')
log.enable_pretty_logging()


class UserAuthHandler(HubAuthenticated, web.RequestHandler):

    # hub_users = {'jupyter', 'martin'}
    # hub_groups = {'jupyter'}
    # allow_admin = True

    async def auth(self):
        """Check if the user is authenticated with JupyterHub if the hub
        API endpoint and token are configured.
        Redirect unauthenticated requests to the JupyterHub login page.
        """

        if self.hub_api_url or self._hubtoken or self._hub_login_url:
            def redirect_to_login():
                self.redirect(url_path_join(self._hub_login_url) +
                              '?' + urlencode({'next': self.request.path}))

            encrypted_cookie = self._hubtoken
            if not encrypted_cookie:
                # no cookie == not authenticated
                raise asyncio.Return(redirect_to_login())

            try:
                # if the hub returns a success code, the user is known
                logging.info(f' hub returns a success code, user is known')
                async_http_client = AsyncHTTPClient()
                response = await self.http_client.fetch(
                    url_path_join(self.hub_api_url,
                                  'authorizations/cookie',
                                  self._hubtoken,
                                  quote(encrypted_cookie, safe='')),
                    headers={
                        'Authorization': 'token ' + self._hubtoken
                    }
                )
            except async_http_client.HTTPError as ex:
                if ex.response.code == 404:
                    # hub does not recognize the cookie == not authenticated
                    logging.info(f' hub does not recognize the cookie 404')
                    raise asyncio.Return(redirect_to_login())
                # let all other errors surface: they're unexpected
                raise ex
            else:
                logging.info(f' hub auth response {response.body}')


class MainHandler(HubOAuthenticated, web.RequestHandler):
    # hub_users = {'jupyter', 'martin'}
    # hub_groups = {'jupyter'}
    # allow_admin = True

    def initialize(self, hub_auth, path):
        self.hub_auth = hub_auth
        self._static = path
        logging.info(f'initialize path: {self._static}')

    @web.authenticated
    def get(self):
        """Render the UI prototype."""
        logging.info(f'web.authenticated +++>')
        logging.info(f'current user{self.get_current_user()}')
        index = os.path.join(self._static, "index.html")
        self.write(open(index).read())


class UserProfileHandler(HubOAuthenticated, web.RequestHandler):

    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "x-requested-with")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.set_header("Content-Type", 'application/json')

    @web.authenticated
    def get(self):
        self.write(json.dumps(self.get_current_user()))
        logging.info(f' get_current_user: {self.get_current_user()}')
        user_model = self.hub_auth(self._usertoken)
        logging.info(f'user_model ==> {user_model}')


class Application(web.Application):
    is_closing = False

    def signal_handler(self, signum, frame):
        logging.info('exiting...')
        self.is_closing = True

    def try_exit(self):
        if self.is_closing:
            ioloop.IOLoop.instance().stop()
            logging.info('exit success')


class CylcUIServer(object):

    def __init__(self, port, static, jhub_service_prefix, usertoken,
                 hubtoken, hub_api_url, hub_base_url, hub_login_url):
        self._port = port
        self._static = str(static)
        self._prefix = str(jhub_service_prefix)
        self._usertoken = usertoken
        self._hubtoken = hubtoken
        self._hub_api_url = hub_api_url
        self._hub_base_url = hub_base_url
        self._hub_login_url = hub_login_url
        if os.path.isabs(str(static)):
            self._static = str(static)
        else:
            script_dir = os.path.dirname(__file__)
            self._static = os.path.abspath(os.path.join(
                script_dir, str(static)))
        logging.info(f' Cylc UI Server running on port {self._port}')
        logging.info(f' serving static files from: {self._static}')
        logging.info(f' self._prefix ==>> {self._prefix}')
        logging.info(f' self._usertoken ==>> {self._usertoken}')
        logging.info(f' self._hubtoken ==>> {self._hubtoken}')
        logging.info(f' self._hub_api_url ==>> {self._hub_api_url}')
        logging.info(f' self._hub_base_url ==>> {self._hub_base_url}')
        logging.info(f' self._hub_login_url ==>> {self._hub_login_url}')
        logging.info(f' JupyterHub Service Prefix: {self._prefix}')

    def _make_app(self):
        return Application(
            static_path=self._static,
            debug=True,
            handlers=[
                (rf'{self._prefix}(.*.(css|js))',
                 web.StaticFileHandler, {'path': self._static}),
                (rf'{self._prefix}((fonts|img)/.*)',
                 web.StaticFileHandler, {'path': self._static}),
                (rf'{self._prefix}(favicon.png)',
                 web.StaticFileHandler, {'path': self._static}),
                (r'/(.*.(css|js))', web.StaticFileHandler,
                 {'path': self._static}),
                (r'/((fonts|img)/.*)', web.StaticFileHandler,
                 {'path': self._static}),
                (r'/(favicon.png)', web.StaticFileHandler,
                 {'path': self._static}),

                (url_path_join(self._prefix, 'userauth'), UserAuthHandler),
                (url_path_join(self._prefix, 'oauth_callback'),
                    HubOAuthCallbackHandler),
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
        logging.info('starting cylc ui')
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
    parser.add_argument('-p', '--port', action='store', dest='port', type=int,
                        default=8888)
    parser.add_argument('-s', '--static', action='store', dest='static',
                        required=True)
    parser.add_argument('-j', '--prefix', action='store', dest='prefix')
    parser.add_argument('-u', '--usertoken', action='store', dest='usertoken')
    parser.add_argument('-t', '--hubtoken', action='store', dest='hubtoken')
    parser.add_argument('-a', '--hub_api_url', action='store',
                        dest='hub_api_url')
    parser.add_argument('-b', '--hub_base_url', action='store',
                        dest='hub_base_url')
    parser.add_argument('-l', '--hub_login_url', action='store',
                        dest='hub_login_url')
    args = parser.parse_args()
    jhub_service_prefix = args.prefix
    logging.info(f'JupyterHub Service Prefix: {jhub_service_prefix}')
    ui_server = CylcUIServer(
        port=args.port, static=args.static,
        jhub_service_prefix=jhub_service_prefix,
        usertoken=args.usertoken, hubtoken=args.hubtoken,
        hub_api_url=args.hub_api_url,
        hub_base_url=args.hub_base_url,
        hub_login_url=args.hub_login_url
        )
    ui_server.start()


if __name__ == '__main__':
    main()


__all__ = ['MainHandler',
           'UserProfileHandler',
           'Application',
           'CylcUIServer',
           'main',
           'UserAuthHandler'
           ]
