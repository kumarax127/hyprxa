import cgi
import io
import json
import logging
import os
import pathlib
import tempfile
from collections.abc import AsyncIterable, Iterable, Mapping
from contextlib import AsyncExitStack, ExitStack
from datetime import datetime
from typing import Any, Callable, Dict, TextIO

import orjson
from httpcore import AsyncConnectionPool, ConnectionPool
from httpx import (
    AsyncHTTPTransport,
    HTTPTransport,
    Limits,
    QueryParams,
    Timeout,
    URL
)
from pydantic import BaseModel

from hyprxa.auth.models import BaseUser
from hyprxa.client.base import HyprxaHttpxAsyncClient, HyprxaHttpxClient
from hyprxa.events.models import Event, EventDocument
from hyprxa.timeseries.models import SubscriptionMessage
from hyprxa.timeseries.sources import AvailableSources
from hyprxa.topics.models import Topic, TopicDocument, TopicQueryResult
from hyprxa.unitops.models import UnitOp, UnitOpDocument, UnitOpQueryResult
from hyprxa.util.sse import SSEParser
from hyprxa.util.status import Status



_LOGGER = logging.getLogger("hyprxa.client")


class HyprxaClient:
    def __init__(
        self,
        api: str,
        **httpx_settings: Any
    ) -> None:
        httpx_settings = httpx_settings.copy() if httpx_settings else {}
        httpx_settings.setdefault("headers", {})

        self._exit_stack = ExitStack()
        self._closed = False
        self._started = False

        if httpx_settings.get("app"):
            raise ValueError(
                "Invalid httpx settings: `app` cannot be set when providing an "
                "api url."
            )
        httpx_settings.setdefault("base_url", api)
        httpx_settings.setdefault(
            "limits",
            Limits(max_connections=25, max_keepalive_connections=10, keepalive_expiry=25)
        )
        self.api_url = api

        httpx_settings.setdefault(
            "timeout",
            Timeout(connect=30, read=30, write=30, pool=30)
        )

        self._client = HyprxaHttpxClient(
            **httpx_settings,
        )

        if isinstance(api, str) and not httpx_settings.get("transport"):
            transport_for_url = getattr(self._client, "_transport_for_url", None)
            if callable(transport_for_url):
                hyprxa_transport = transport_for_url(URL(api))
                if isinstance(hyprxa_transport, HTTPTransport):
                    pool = getattr(hyprxa_transport, "_pool", None)
                    if isinstance(pool, ConnectionPool):
                        pool._retries = 3

    def whoami(self) -> BaseUser:
        """Send a GET request to /users/whoami."""
        return self._get("/users/whoami", BaseUser)

    def create_event_topic(self, topic: Topic) -> Status:
        """Send a POST request to /events/topics/save."""
        data = topic.json()
        return self._post("/events/topics/save", Status, data)
    
    def get_topic(self, topic: str) -> TopicDocument:
        """Send a GET request to /events/topics/{topic}."""
        return self._get(f"/events/topics/{topic}", TopicDocument)
    
    def get_topics(self) -> TopicQueryResult:
        """Set a GET request to /events/topics."""
        return self._get("/events/topics", TopicQueryResult)
    
    def publish_event(self, event: Event) -> Status:
        """Send a POST request to /events/publish/{event.topic}."""
        data = event.json()
        return self._post(f"/events/publish/{event.topic}", Status, data)
    
    def get_event(self, topic: str, routing_key: str | None = None) -> EventDocument:
        """Send a GET request to /events/{topic}/last."""
        params = QueryParams(routing_key=routing_key)
        return self._get(f"/events/{topic}/last", EventDocument, params=params)
    
    def stream_events(
        self,
        topic: str,
        routing_key: str | None = None
    ) -> Iterable[EventDocument]:
        """Send a GET request to /events/stream/{topic} and stream events."""
        params = QueryParams(routing_key=routing_key)
        path = f"/events/stream/{topic}"
        for data in self._sse("GET", path, params):
            yield EventDocument(**data)

    def download_events(
        self,
        topic: str,
        destination: os.PathLike | TextIO = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        routing_key: str | None = None,
        timezone: str | None = None
    ) -> None:
        """Send a GET request to /events/{topic}/recorded.
        
        Data is in CSV format.
        """
        path = f"/events/{topic}/recorded"
        params=QueryParams(
            start_time=start_time,
            end_time=end_time,
            routing_key=routing_key,
            timezone=timezone
        )
        self._download_to_csv(
            method="GET",
            path=path,
            params=params,
            destination=destination
        )

    def get_sources(self) -> AvailableSources:
        """Send a GET request to /timeseries/sources."""
        return self._get(f"/timeseries/sources", AvailableSources)

    def create_unitop(self, unitop: UnitOp) -> Status:
        """Send a POST request to /timeseries/unitop/save."""
        data = unitop.json()
        return self._post("/timeseries/unitop/save", Status, data)
    
    def get_unitop(self, unitop: str) -> UnitOpDocument:
        """Send a GET request to /timeseries/unitop/{unitop}."""
        return self._get(f"/timeseries/unitop/{unitop}", UnitOpDocument)
    
    def get_unitops(self, q: str | Dict[str, Any]) -> UnitOpQueryResult:
        """Set a GET request to /events/topics."""
        if isinstance(q, dict):
            q = json.dumps(q)
        
        params = QueryParams(q=q)
        return self._get("/timeseries/unitop/search", UnitOpQueryResult, params=params)
    
    def stream_messages(self, unitop: str) -> Iterable[SubscriptionMessage]:
        """Send a GET request to /timeseries/stream/{unitop} and stream data."""
        path = f"/timeseries/stream/{unitop}"
        for data in self._sse("GET", path):
            yield SubscriptionMessage.parse_obj(data)

    def download_data(
        self,
        unitop: str,
        destination: os.PathLike | TextIO = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        timezone: str | None = None,
        scan_rate: int = 5
    ) -> None:
        """Send a GET request to /timeseries/{unitop}/recorded
        
        Data is in CSV format.
        """
        path = f"/timeseries/{unitop}/recorded"
        params=QueryParams(
            start_time=start_time,
            end_time=end_time,
            timezone=timezone,
            scan_rate=scan_rate
        )
        self._download_to_csv(
            method="GET",
            path=path,
            params=params,
            destination=destination
        )

    def _get(
        self,
        path: str,
        response_model: Callable[[Mapping], Any],
        params: QueryParams | None = None
    ) -> BaseModel:
        """Handle GET request and return the response model."""
        response = self._client.get(path, params=params)
        content = response.read()
        data = orjson.loads(content)
        return response_model(**data)
    
    def _post(
        self,
        path: str,
        response_model: Callable[[Mapping], Any],
        json: Any,
        params: QueryParams | None = None,
    ) -> BaseModel:
        """Handle POST request and return the response model."""
        response = self._client.post(path, params=params, json=json)
        content = response.read()
        data = orjson.loads(content)
        return response_model(**data)
    
    def _sse(
        self,
        method: str,
        path: str,
        params: QueryParams | None = None,
        json_: Any | None = None
    ) -> Iterable[Any]:
        """Handle SSE endpoints yielding 'data' events as bytes."""
        parser = SSEParser(_LOGGER)
        with self._client.stream(method, path, params=params, json=json_) as response:
            for data in response.iter_bytes():
                parser.feed(data)
                for event in parser.events():
                    if event.event == "message":
                        yield json.loads(event.data)

    def _download_to_csv(
        self,
        method: str,
        path: str,
        params: QueryParams | None = None,
        json: Any | None = None,
        destination: os.PathLike | TextIO = None,
    ) -> None:
        """Download CSV data to TextIO object."""
        def transfer_temp_to_file(tfh: TextIO, fh: TextIO) -> None:
            while True:
                b = tfh.read(10_240)
                if not b:
                    break
                fh.write(b)

        if destination is not None:
            if isinstance(destination, io.TextIOBase):
                if not destination.writable():
                    raise ValueError(f"FileLike destination must be writable")
            else:
                destination = pathlib.Path(destination)
                if destination.suffix and destination.suffix.lower() != ".csv":
                    raise ValueError("PathLike destination must be '.csv'")
        else:
            destination = pathlib.Path("~").expanduser().joinpath("./.hyprxa/downloads")
            os.makedirs(destination, exist_ok=True)
        
        with self._client.stream(
            method,
            path,
            params=params,
            json=json,
            headers={"Accept": "text/csv"}
        ) as response:
            if isinstance(destination, pathlib.Path) and not destination.suffix:
                filename: str = None
                header = response.headers.get("content-disposition")
                if header:
                    try:
                        filename = cgi.parse_header(header)[1].get(filename)
                    except Exception:
                        pass
                if not filename:
                    filename = f"{int(datetime.now().timestamp()*1_000_000)}.csv"
                destination = destination.joinpath(f"./{filename}")
            
            with tempfile.SpooledTemporaryFile(max_size=10_485_760, mode="w+") as tfh:
                for line in response.iter_lines():
                    tfh.write(line)
                else:
                    tfh.seek(0)
                    if isinstance(destination, pathlib.Path):
                        with open(destination, mode='w') as fh:
                            transfer_temp_to_file(tfh, fh)
                    else:
                        transfer_temp_to_file(tfh, fh)

    def __enter__(self):
        """Start the client.
        
        If the client is already started, this will raise an exception.
        
        If the client is already closed, this will raise an exception. Use a new client
        instance instead.
        """
        if self._closed:
            raise RuntimeError(
                "The client cannot be started again after closing. "
                "Retrieve a new client with `get_client()` instead."
            )

        if self._started:
            raise RuntimeError("The client cannot be started more than once.")

        self._exit_stack.__enter__()
        _LOGGER.debug("Connecting to API at %s", self.api_url)
        self._exit_stack.enter_context(self._client)

        self._started = True

        return self

    def __exit__(self, *exc_info):
        """Shutdown the client."""
        self._closed = True
        return self._exit_stack.__exit__(*exc_info)

    async def __aenter__(self):
        raise RuntimeError(
            "The `HyprxaClient` must be entered with an synchronous context. "
            "Use 'with HyprxaClient(...)' not 'async with HyprxaClient(...)'"
        )

    def __aexit__(self, *_):
        assert False, "This should never be called but must be defined for __enter__"


class HyprxaAsyncClient:
    def __init__(
        self,
        api: str,
        **httpx_settings: Any
    ) -> None:
        httpx_settings = httpx_settings.copy() if httpx_settings else {}
        httpx_settings.setdefault("headers", {})

        self._exit_stack = AsyncExitStack()
        self._closed = False
        self._started = False

        if httpx_settings.get("app"):
            raise ValueError(
                "Invalid httpx settings: `app` cannot be set when providing an "
                "api url."
            )
        httpx_settings.setdefault("base_url", api)
        httpx_settings.setdefault(
            "limits",
            Limits(max_connections=25, max_keepalive_connections=10, keepalive_expiry=25)
        )
        self.api_url = api

        httpx_settings.setdefault(
            "timeout",
            Timeout(connect=30, read=30, write=30, pool=30)
        )

        self._client = HyprxaHttpxAsyncClient(
            **httpx_settings,
        )

        if isinstance(api, str) and not httpx_settings.get("transport"):
            transport_for_url = getattr(self._client, "_transport_for_url", None)
            if callable(transport_for_url):
                hyprxa_transport = transport_for_url(URL(api))
                if isinstance(hyprxa_transport, AsyncHTTPTransport):
                    pool = getattr(hyprxa_transport, "_pool", None)
                    if isinstance(pool, AsyncConnectionPool):
                        pool._retries = 3

    async def whoami(self) -> BaseUser:
        """Send a GET request to /users/whoami."""
        return await self._get("/users/whoami", BaseUser)

    async def create_event_topic(self, topic: Topic) -> Status:
        """Send a POST request to /events/topics/save."""
        data = topic.json()
        return await self._post("/events/topics/save", Status, data)
    
    async def get_topic(self, topic: str) -> TopicDocument:
        """Send a GET request to /events/topics/{topic}."""
        return await self._get(f"/events/topics/{topic}", TopicDocument)
    
    async def get_topics(self) -> TopicQueryResult:
        """Set a GET request to /events/topics."""
        return await self._get("/events/topics", TopicQueryResult)
    
    async def publish_event(self, event: Event) -> Status:
        """Send a POST request to /events/publish/{event.topic}."""
        data = event.json()
        return await self._post(f"/events/publish/{event.topic}", Status, data)
    
    async def get_event(self, topic: str, routing_key: str | None = None) -> EventDocument:
        """Send a GET request to /events/{topic}/last."""
        params = QueryParams(routing_key=routing_key)
        return await self._get(f"/events/{topic}/last", EventDocument, params=params)
    
    async def stream_events(
        self,
        topic: str,
        routing_key: str | None = None
    ) -> AsyncIterable[EventDocument]:
        """Send a GET request to /events/stream/{topic} and stream events."""
        params = QueryParams(routing_key=routing_key)
        path = f"/events/stream/{topic}"
        async for data in self._sse("GET", path, params):
            yield EventDocument(**data)

    async def download_events(
        self,
        topic: str,
        destination: os.PathLike | TextIO = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        routing_key: str | None = None,
        timezone: str | None = None
    ) -> None:
        """Send a GET request to /events/{topic}/recorded.
        
        Data is in CSV format.
        """
        path = f"/events/{topic}/recorded"
        params=QueryParams(
            start_time=start_time,
            end_time=end_time,
            routing_key=routing_key,
            timezone=timezone
        )
        await self._download_to_csv(
            method="GET",
            path=path,
            params=params,
            destination=destination
        )

    async def get_sources(self) -> AvailableSources:
        """Send a GET request to /timeseries/sources."""
        return await self._get(f"/timeseries/sources", AvailableSources)

    async def create_unitop(self, unitop: UnitOp) -> Status:
        """Send a POST request to /timeseries/unitop/save."""
        data = unitop.json()
        return await self._post("/timeseries/unitop/save", Status, data)
    
    async def get_unitop(self, unitop: str) -> UnitOpDocument:
        """Send a GET request to /timeseries/unitop/{unitop}."""
        return await self._get(f"/timeseries/unitop/{unitop}", UnitOpDocument)
    
    async def get_unitops(self, q: str | Dict[str, Any]) -> UnitOpQueryResult:
        """Set a GET request to /events/topics."""
        if isinstance(q, dict):
            q = json.dumps(q)
        
        params = QueryParams(q=q)
        return await self._get("/timeseries/unitop/search", UnitOpQueryResult, params=params)
    
    async def stream_messages(self, unitop: str) -> AsyncIterable[SubscriptionMessage]:
        """Send a GET request to /timeseries/stream/{unitop} and stream data."""
        path = f"/timeseries/stream/{unitop}"
        async for data in self._sse("GET", path):
            yield SubscriptionMessage.parse_obj(data)

    async def download_data(
        self,
        unitop: str,
        destination: os.PathLike | TextIO = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        timezone: str | None = None,
        scan_rate: int = 5
    ) -> None:
        """Send a GET request to /timeseries/{unitop}/recorded
        
        Data is in CSV format.
        """
        path = f"/timeseries/{unitop}/recorded"
        params=QueryParams(
            start_time=start_time,
            end_time=end_time,
            timezone=timezone,
            scan_rate=scan_rate
        )
        await self._download_to_csv(
            method="GET",
            path=path,
            params=params,
            destination=destination
        )

    async def _get(
        self,
        path: str,
        response_model: Callable[[Mapping], Any],
        params: QueryParams | None = None
    ) -> BaseModel:
        """Handle GET request and return the response model."""
        response = await self._client.get(path, params=params)
        content = await response.aread()
        data = orjson.loads(content)
        return response_model(**data)
    
    async def _post(
        self,
        path: str,
        response_model: Callable[[Mapping], Any],
        json: Any,
        params: QueryParams | None = None,
    ) -> BaseModel:
        """Handle POST request and return the response model."""
        response = await self._client.post(path, params=params, json=json)
        content = await response.aread()
        data = orjson.loads(content)
        return response_model(**data)
    
    async def _sse(
        self,
        method: str,
        path: str,
        params: QueryParams | None = None,
        json_: Any | None = None
    ) -> AsyncIterable[Any]:
        """Handle SSE endpoints yielding 'data' events as bytes."""
        parser = SSEParser(_LOGGER)
        async with self._client.stream(method, path, params=params, json=json_) as response:
            async for data in response.aiter_bytes():
                parser.feed(data)
                for event in parser.events():
                    if event.event == "message":
                        yield json.loads(event.data)

    async def _download_to_csv(
        self,
        method: str,
        path: str,
        params: QueryParams | None = None,
        json: Any | None = None,
        destination: os.PathLike | TextIO = None,
    ) -> None:
        """Download CSV data to TextIO object."""
        def transfer_temp_to_file(tfh: TextIO, fh: TextIO) -> None:
            while True:
                b = tfh.read(10_240)
                if not b:
                    break
                fh.write(b)

        if destination is not None:
            if isinstance(destination, io.TextIOBase):
                if not destination.writable():
                    raise ValueError(f"FileLike destination must be writable")
            else:
                destination = pathlib.Path(destination)
                if destination.suffix and destination.suffix.lower() != ".csv":
                    raise ValueError("PathLike destination must be '.csv'")
        else:
            destination = pathlib.Path("~").expanduser().joinpath("./.hyprxa/downloads")
            os.makedirs(destination, exist_ok=True)
        
        async with self._client.stream(
            method,
            path,
            params=params,
            json=json,
            headers={"Accept": "text/csv"}
        ) as response:
            if isinstance(destination, pathlib.Path) and not destination.suffix:
                filename: str = None
                header = response.headers.get("content-disposition")
                if header:
                    try:
                        filename = cgi.parse_header(header)[1].get(filename)
                    except Exception:
                        pass
                if not filename:
                    filename = f"{int(datetime.now().timestamp()*1_000_000)}.csv"
                destination = destination.joinpath(f"./{filename}")
            
            with tempfile.SpooledTemporaryFile(max_size=10_485_760, mode="w+") as tfh:
                async for line in response.aiter_lines():
                    tfh.write(line)
                else:
                    tfh.seek(0)
                    if isinstance(destination, pathlib.Path):
                        with open(destination, mode='w') as fh:
                            transfer_temp_to_file(tfh, fh)
                    else:
                        transfer_temp_to_file(tfh, fh)

    async def __aenter__(self):
        """Start the client.
        
        If the client is already started, this will raise an exception.
        
        If the client is already closed, this will raise an exception. Use a new client
        instance instead.
        """
        if self._closed:
            raise RuntimeError(
                "The client cannot be started again after closing. "
                "Retrieve a new client with `get_client()` instead."
            )

        if self._started:
            raise RuntimeError("The client cannot be started more than once.")

        await self._exit_stack.__aenter__()
        _LOGGER.debug("Connecting to API at %s", self.api_url)
        await self._exit_stack.enter_async_context(self._client)

        self._started = True

        return self

    async def __aexit__(self, *exc_info):
        """Shutdown the client."""
        self._closed = True
        return await self._exit_stack.__aexit__(*exc_info)

    def __enter__(self):
        raise RuntimeError(
            "The `HyprxaAsyncClient` must be entered with an async context. Use "
            "'async with HyprxaAsyncClient(...)' not 'with HyprxaAsyncClient(...)'"
        )

    def __exit__(self, *_):
        assert False, "This should never be called but must be defined for __enter__"