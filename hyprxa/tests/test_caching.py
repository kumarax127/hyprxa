import pytest
import random
import functools

from hyprxa.caching import memo

memo = functools.partial(
    memo,
    ttl=86400
)

def test_cache_mutable_arg():
    arguments = [1, 2, 3]

    @memo
    def random_function(mutable_arg):
        return mutable_arg + [random.randint(0, 100) for _ in range(10)]  

    first_time = random_function(arguments)
    second_time = random_function(arguments)

    assert first_time == second_time

    arguments.append(4) #arguments: 1, 2, 3, 4
    third_time = random_function(arguments)

    assert first_time != third_time 

def test_cache_source_code_change():
    @memo
    def random_function():
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
    def random_function():
        return [random.randint(0, 100) for _ in range(10)]

    third_time = random_function()

    assert first_time != third_time
    assert isinstance(third_time, tuple)

    @memo
    def random_function():
        return [random.randint(0, 100) for _ in range(10)]

    fourth_time = random_function()
    assert fourth_time == first_time