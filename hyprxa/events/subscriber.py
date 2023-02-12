from collections.abc import AsyncIterable
from typing import Set

from hyprxa.events.models import TopicSubscription
from hyprxa.integrations import BaseSubscriber, SubscriberCodes



class EventSubscriber(BaseSubscriber):
    @property
    def subscriptions(self) -> Set[TopicSubscription]:
        return super().subscriptions

    async def __aiter__(self) -> AsyncIterable[str]:
        if self.stopped:
            return
        while not self.stopped:
            if not self._data:
                code = await self.wait()
                if code is SubscriberCodes.STOPPED:
                    return
            # Pop messages from the data queue until there are no messages
            # left
            while True:
                try:
                    yield self._data.popleft()
                except IndexError:
                    # Empty queue
                    break