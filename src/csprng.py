import os

class CSPRNGError(RuntimeError):
    """Не удалось получить случайные байты от ОС."""


def generate_random_bytes(num_bytes: int) -> bytes:
    if not isinstance(num_bytes, int) or isinstance(num_bytes, bool):
        raise TypeError(f"num_bytes должен быть int, получено {type(num_bytes).__name__}.")
    if num_bytes < 0:
        raise ValueError(f"num_bytes не может быть отрицательным, получено {num_bytes}.")

    try:
        data = os.urandom(num_bytes)
    except (OSError, NotImplementedError) as e:
        # os.urandom выбрасывает NotImplementedError, если источник энтропии ОС не найден,
        # и OSError — если системный вызов завершился с ошибкой
        raise CSPRNGError(f"системный источник случайности недоступен: {e}") from e

    if len(data) != num_bytes:
        raise CSPRNGError(f"получено {len(data)} случайных байт вместо {num_bytes}.")
    return data
