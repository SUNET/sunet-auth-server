# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
from __future__ import annotations

import atexit
import random
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from typing import Any, Optional, Sequence, Type, cast

from loguru import logger
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

from auth_server.time_utils import utc_now

__author__ = "lundberg"


class TemporaryInstance(ABC):
    """Singleton to manage a temporary instance of something needed when testing.

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.
    """

    _instance = None

    def __init__(self, max_retry_seconds: int):
        self._conn: Optional[Any] = None  # self._conn should be initialised by subclasses in `setup_conn'
        self._tmpdir = tempfile.mkdtemp()
        self._port = random.randint(40000, 65535)
        self._logfile = open(f"/tmp/{self.__class__.__name__}-{self.port}.log", "w")

        start_time = utc_now()
        self._process = subprocess.Popen(self.command, stdout=self._logfile, stderr=subprocess.STDOUT)

        interval = 0.2
        count = 0
        while True:
            count += 1
            time.sleep(interval)

            # Call a function of the subclass of this ABC to see if the instance is operational yet
            _res = self.setup_conn()

            time_now = utc_now()
            delta = time_now - start_time
            age = delta.total_seconds()
            if _res:
                logger.info(f"{self} instance started after {age} seconds (attempt {count})")
                break
            if age > max_retry_seconds:
                logger.error(f"{self} instance failed to start after {age} seconds")
                logger.error(f"{self} instance output:\n{self.output}")
                raise RuntimeError(f"{self} instance failed to start after {age} seconds")
            if count <= 3:
                # back off slightly
                interval += interval

    @classmethod
    def get_instance(cls: Type[TemporaryInstance], max_retry_seconds: int = 60) -> TemporaryInstance:
        """
        Start a new temporary instance, or retrieve an already started one.

        :param max_retry_seconds: Time allowed for the instance to start
        :return:
        """
        if cls._instance is None:
            cls._instance = cls(max_retry_seconds=max_retry_seconds)
            atexit.register(cls._instance.shutdown)
        return cls._instance

    @abstractmethod
    def setup_conn(self) -> bool:
        """
        Initialise and test a connection of the instance in self._conn.

        Return True on success.
        """
        raise NotImplementedError("All subclasses of TemporaryInstance must implement setup_conn")

    @property
    @abstractmethod
    def conn(self) -> Any:
        """Return the initialised _conn instance. No default since it ought to be typed in the subclasses."""
        raise NotImplementedError("All subclasses of TemporaryInstance should implement the conn property")

    @property
    @abstractmethod
    def command(self) -> Sequence[str]:
        """This is the shell command to start the temporary instance."""
        raise NotImplementedError("All subclasses of TemporaryInstance must implement the command property")

    @property
    def port(self) -> int:
        return self._port

    @property
    def tmpdir(self) -> str:
        return self._tmpdir

    @property
    def output(self) -> str:
        with open(self._logfile.name, "r") as fd:
            _output = "".join(fd.readlines())
        return _output

    def shutdown(self):
        logger.debug(f"{self} output at shutdown:\n{self.output}")
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None
        self._logfile.close()
        if "tmp" in self._tmpdir:
            shutil.rmtree(self._tmpdir, ignore_errors=True)


class MongoTemporaryInstance(TemporaryInstance):
    """Singleton to manage a temporary MongoDB instance

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.
    """

    @property
    def command(self) -> Sequence[str]:
        return ["docker", "run", "--rm", "-p", f"{self._port!s}:27017", "docker.sunet.se/eduid/mongodb:latest"]

    def setup_conn(self) -> bool:
        try:
            self._conn = MongoClient("localhost", self._port)
            logger.info(f"Connected to temporary mongodb instance: {self._conn}")
        except ConnectionFailure:
            return False
        return True

    @property
    def conn(self) -> MongoClient:
        if self._conn is None:
            raise RuntimeError("Missing temporary MongoDB instance")
        return self._conn

    @property
    def uri(self):
        return f"mongodb://localhost:{self.port}"

    def shutdown(self):
        if self._conn:
            logger.info(f"Closing connection {self._conn}")
            self._conn.close()
            self._conn = None
        super().shutdown()

    @classmethod
    def get_instance(cls: Type[MongoTemporaryInstance], max_retry_seconds: int = 20) -> MongoTemporaryInstance:
        return cast(MongoTemporaryInstance, super().get_instance(max_retry_seconds=max_retry_seconds))
