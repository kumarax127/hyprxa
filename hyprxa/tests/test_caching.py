import pytest
import random
import pickle
import logging

from typing import List 

from hyprxa.caching import memo 
from hyprxa.caching.memo import MemoCache, MemoizedFunction, memo_cache_collection
from hyprxa.caching.core import make_function_key, make_value_key

from pymemcache import PooledClient

log = logging.getLogger("hyprxa.caching")

def test_cache_mutable_arg():
    arguments = [1, 2, 3]

    @memo
    def random_function(mutable_arg) -> List[int]:
        return mutable_arg + [random.randint(0, 100) for _ in range(10)]  

    first_time = random_function(arguments)
    second_time = random_function(arguments)

    assert first_time == second_time

    arguments.append(4) #arguments: 1, 2, 3, 4
    third_time = random_function(arguments)

    assert first_time != third_time 

def test_cache_source_code_change():
    @memo
    def random_function() -> List[int]:
        return [random.randint(0, 100) for _ in range(10)]

    first_time = random_function()

    second_time = random_function()
    
    assert first_time == second_time

    def wrapper(func):
        def change_to_tuple(*args, **kwargs):
            return tuple(func(*args, **kwargs))
        return change_to_tuple

    @memo 
    @wrapper
    def random_function() -> List[int]:
        return [random.randint(0, 100) for _ in range(10)]

    third_time = random_function()

    assert first_time != third_time
    assert isinstance(third_time, tuple)

    @memo
    def random_function() -> List[int]:
        return [random.randint(0, 100) for _ in range(10)]

    fourth_time = random_function()
    assert fourth_time == first_time


def test_cache_placement_no_args():
    client: PooledClient = memo.get_client()

    def random_function() -> List[int]:
        return [random.randint(0, 100) for _ in range(10)]

    cached_func = MemoizedFunction(random_function, 86400)
    function_key = make_function_key(cached_func.cache_type, cached_func.func)
    value_key = make_value_key(cached_func.cache_type, cached_func.func)

    generated_key = f"{function_key}-{value_key}"

    # call memo function
    first_time = memo(random_function)()

    result = client.get(generated_key)

    assert result is not None
    assert pickle.loads(result) == first_time


    rf_cache = memo_cache_collection.get_cache(random_function, function_key, "random_function", 86400)

    assert rf_cache.read_result(value_key) == first_time


def test_cache_placement_args():
    client: PooledClient = memo.get_client()

    def random_function(args: List[int]) -> List[int]:
        return args + [random.randint(0, 100) for _ in range(10)]

    cached_func = MemoizedFunction(random_function, 86400)

    function_key = make_function_key(cached_func.cache_type, cached_func.func)

    args = [1, 2, 3]

    first_value_key = make_value_key(cached_func.cache_type, cached_func.func, args)

    # call memo function
    first_time = memo(random_function)(args)

    first_key = f"{function_key}-{first_value_key}"

    assert client.get(first_key) is not None
    assert pickle.loads(client.get(first_key)) == first_time
    
    # arguments changed keys should be different
    args.append(4)

    second_value_key = make_value_key(cached_func.cache_type, cached_func.func, args)
    assert first_value_key != second_value_key

    second_time = memo(random_function)(args)
    assert first_time != second_time

    second_key = f"{function_key}-{second_value_key}"

    assert client.get(second_key) is not None
    assert pickle.loads(client.get(second_key)) == second_time


### Test 
    
