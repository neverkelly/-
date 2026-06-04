"""
Лабораторная работа №8
Реализация системы хранения субъектов и объектов по модели Белла-ЛаПадулы.

Модель Белла-ЛаПадулы (Bell-LaPadula, BLP) — формальная модель
обеспечения конфиденциальности информации в системах с мандатным управлением
доступом (MAC).

Основные правила:
  1. Простое правило безопасности (ss-property / No Read Up):
       субъект может ЧИТАТЬ объект только если его уровень доступа >= уровня объекта.
  2. Правило «звезды» (*-property / No Write Down):
       субъект может ПИСАТЬ в объект только если уровень объекта >= текущего уровня субъекта.
  3. Дискреционное правило (ds-property):
       доступ разрешён только если он указан в матрице разграничения доступа (ACL).

При изменении текущего уровня субъекта система автоматически проверяет
все активные операции и при необходимости отзывает их.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ─────────────────────────────────────────────
# 1. Уровни безопасности (Security Levels)
# ─────────────────────────────────────────────

class Level(enum.IntEnum):
    """Иерархия уровней конфиденциальности (от низшего к высшему)."""
    UNCLASSIFIED    = 0   # Несекретно
    CONFIDENTIAL    = 1   # Конфиденциально
    SECRET          = 2   # Секретно
    TOP_SECRET      = 3   # Совершенно секретно

    def __str__(self) -> str:
        labels = {
            0: "Несекретно",
            1: "Конфиденциально",
            2: "Секретно",
            3: "Сов. секретно",
        }
        return labels[self.value]


# ─────────────────────────────────────────────
# 2. Виды доступа
# ─────────────────────────────────────────────

class AccessMode(enum.Enum):
    READ    = "read"    # Чтение
    WRITE   = "write"   # Запись
    EXECUTE = "execute" # Исполнение (только ds-property)

    def __str__(self) -> str:
        return self.value


# ─────────────────────────────────────────────
# 3. Субъекты и объекты
# ─────────────────────────────────────────────

@dataclass
class Object:
    """Информационный объект с фиксированным уровнем конфиденциальности."""
    name:  str
    level: Level
    data:  str = ""   # содержимое объекта

    def __str__(self) -> str:
        return f"Объект '{self.name}' [{self.level}]"


@dataclass
class Subject:
    """
    Субъект (пользователь / процесс).

    max_level       — максимальный уровень допуска (не меняется).
    current_level   — текущий уровень, с которым субъект работает прямо сейчас.
                      Может понижаться/повышаться, но не выше max_level.
    acl             — матрица дискреционного доступа: {object_name: set(AccessMode)}.
    active_accesses — список активных операций (object_name, AccessMode).
    """
    name:           str
    max_level:      Level
    current_level:  Level
    acl:            Dict[str, Set[AccessMode]] = field(default_factory=dict)
    active_accesses: List[Tuple[str, AccessMode]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.current_level > self.max_level:
            raise ValueError(
                f"Текущий уровень {self.current_level} не может превышать "
                f"максимальный допуск {self.max_level} субъекта '{self.name}'."
            )

    def __str__(self) -> str:
        return (
            f"Субъект '{self.name}' "
            f"[текущий: {self.current_level}, макс.: {self.max_level}]"
        )


# ─────────────────────────────────────────────
# 4. Результат проверки доступа
# ─────────────────────────────────────────────

@dataclass
class AccessResult:
    granted:  bool
    reason:   str

    def __str__(self) -> str:
        status = "РАЗРЕШЁН" if self.granted else "ОТКАЗАНО"
        return f"[{status}] {self.reason}"


# ─────────────────────────────────────────────
# 5. Система BLP
# ─────────────────────────────────────────────

class BellLaPadulaSystem:
    """
    Система контроля доступа по модели Белла-ЛаПадулы.

    Хранит субъекты и объекты, проверяет запросы доступа,
    управляет активными сессиями и обеспечивает корректность
    при изменении текущего уровня субъекта.
    """

    def __init__(self, name: str = "BLP System") -> None:
        self.name:     str                    = name
        self.subjects: Dict[str, Subject]     = {}
        self.objects:  Dict[str, Object]      = {}
        self._log:     List[str]              = []

    # ── Управление субъектами ──────────────────

    def add_subject(self, subject: Subject) -> None:
        self.subjects[subject.name] = subject
        self._log_event(f"Добавлен {subject}")

    def add_object(self, obj: Object) -> None:
        self.objects[obj.name] = obj
        self._log_event(f"Добавлен {obj}")

    def grant_discretionary(
        self,
        subject_name: str,
        object_name:  str,
        modes:        Set[AccessMode],
    ) -> None:
        """Выдать дискреционные права субъекту на объект."""
        s = self._get_subject(subject_name)
        o = self._get_object(object_name)
        s.acl.setdefault(o.name, set()).update(modes)
        modes_str = ", ".join(str(m) for m in modes)
        self._log_event(
            f"ACL: субъекту '{subject_name}' выданы права [{modes_str}] "
            f"на объект '{object_name}'"
        )

    def revoke_discretionary(
        self,
        subject_name: str,
        object_name:  str,
        modes:        Set[AccessMode],
    ) -> None:
        """Отозвать дискреционные права."""
        s = self._get_subject(subject_name)
        if object_name in s.acl:
            s.acl[object_name] -= modes
            modes_str = ", ".join(str(m) for m in modes)
            self._log_event(
                f"ACL: у субъекта '{subject_name}' отозваны права [{modes_str}] "
                f"на объект '{object_name}'"
            )

    # ── Проверка и выполнение доступа ─────────

    def request_access(
        self,
        subject_name: str,
        object_name:  str,
        mode:         AccessMode,
    ) -> AccessResult:
        """
        Проверить запрос доступа и, если разрешён, зафиксировать активный доступ.
        """
        result = self._check_access(subject_name, object_name, mode)
        msg = (
            f"Запрос [{mode}] субъект='{subject_name}' объект='{object_name}': "
            f"{result}"
        )
        self._log_event(msg)

        if result.granted:
            subj = self.subjects[subject_name]
            subj.active_accesses.append((object_name, mode))

        return result

    def release_access(
        self,
        subject_name: str,
        object_name:  str,
        mode:         AccessMode,
    ) -> None:
        """Завершить активный доступ (освобождение ресурса)."""
        subj = self._get_subject(subject_name)
        try:
            subj.active_accesses.remove((object_name, mode))
            self._log_event(
                f"Доступ завершён: субъект='{subject_name}' [{mode}] "
                f"объект='{object_name}'"
            )
        except ValueError:
            pass

    def read_object(self, subject_name: str, object_name: str) -> Optional[str]:
        """Прочитать данные объекта (если активный read-доступ разрешён)."""
        subj = self._get_subject(subject_name)
        if (object_name, AccessMode.READ) not in subj.active_accesses:
            # Пробуем запросить доступ на лету
            r = self.request_access(subject_name, object_name, AccessMode.READ)
            if not r.granted:
                return None
        return self.objects[object_name].data

    def write_object(
        self,
        subject_name: str,
        object_name:  str,
        data:         str,
    ) -> bool:
        """Записать данные в объект (если активный write-доступ разрешён)."""
        subj = self._get_subject(subject_name)
        if (object_name, AccessMode.WRITE) not in subj.active_accesses:
            r = self.request_access(subject_name, object_name, AccessMode.WRITE)
            if not r.granted:
                return False
        self.objects[object_name].data = data
        self._log_event(
            f"Запись: субъект='{subject_name}' -> объект='{object_name}'"
        )
        return True

    # ── Изменение текущего уровня субъекта ────

    def change_subject_level(
        self,
        subject_name: str,
        new_level:    Level,
    ) -> List[str]:
        """
        Изменить текущий уровень доступа субъекта.

        После изменения уровня система проверяет все активные доступы субъекта.
        Те, что нарушают правила BLP при новом уровне, автоматически отзываются.

        Возвращает список отозванных доступов.
        """
        subj = self._get_subject(subject_name)

        if new_level > subj.max_level:
            raise ValueError(
                f"Новый уровень {new_level} превышает максимальный допуск "
                f"{subj.max_level} субъекта '{subject_name}'."
            )

        old_level = subj.current_level
        subj.current_level = new_level
        self._log_event(
            f"Уровень субъекта '{subject_name}': {old_level} -> {new_level}"
        )

        # Проверяем и при необходимости отзываем активные доступы
        revoked: List[str] = []
        still_valid: List[Tuple[str, AccessMode]] = []

        for (obj_name, mode) in list(subj.active_accesses):
            check = self._check_access_blp_only(subj, obj_name, mode)
            if check.granted:
                still_valid.append((obj_name, mode))
            else:
                revoked.append(
                    f"  Отозван [{mode}] на '{obj_name}': {check.reason}"
                )
                self._log_event(
                    f"  Отозван активный доступ [{mode}] субъект='{subject_name}' "
                    f"объект='{obj_name}': {check.reason}"
                )

        subj.active_accesses = still_valid

        if revoked:
            self._log_event(
                f"Итого отозвано {len(revoked)} активных доступов "
                f"у субъекта '{subject_name}'."
            )

        return revoked

    # ── Отображение состояния ──────────────────

    def show_state(self) -> None:
        sep = "─" * 60
        print(f"\n{'═' * 60}")
        print(f"  {self.name}  |  Текущее состояние")
        print(f"{'═' * 60}")

        print("\n[ СУБЪЕКТЫ ]")
        print(sep)
        for s in self.subjects.values():
            print(f"  {s}")
            if s.acl:
                for obj_name, modes in s.acl.items():
                    modes_str = ", ".join(str(m) for m in modes)
                    print(f"      ACL -> '{obj_name}': [{modes_str}]")
            if s.active_accesses:
                for obj_name, mode in s.active_accesses:
                    print(f"      Активный доступ: [{mode}] на '{obj_name}'")

        print(f"\n[ ОБЪЕКТЫ ]")
        print(sep)
        for o in self.objects.values():
            data_preview = (o.data[:40] + "…") if len(o.data) > 40 else o.data
            print(f"  {o}  данные='{data_preview}'")

    def show_log(self, last_n: int = 0) -> None:
        entries = self._log if not last_n else self._log[-last_n:]
        print(f"\n{'─' * 60}")
        print(f"  Журнал событий ({len(entries)} из {len(self._log)})")
        print(f"{'─' * 60}")
        for i, entry in enumerate(entries, 1):
            print(f"  {i:>3}. {entry}")

    # ── Внутренние методы ──────────────────────

    def _check_access(
        self,
        subject_name: str,
        object_name:  str,
        mode:         AccessMode,
    ) -> AccessResult:
        subj = self._get_subject(subject_name)
        obj  = self._get_object(object_name)

        # 1. Дискреционная проверка (ds-property)
        allowed_modes = subj.acl.get(obj.name, set())
        if mode not in allowed_modes:
            return AccessResult(
                False,
                f"ds-property: у субъекта '{subject_name}' нет дискреционного "
                f"права [{mode}] на '{object_name}'."
            )

        # 2. Мандатные проверки BLP
        return self._check_access_blp_only(subj, object_name, mode)

    def _check_access_blp_only(
        self,
        subj:        Subject,
        object_name: str,
        mode:        AccessMode,
    ) -> AccessResult:
        """Проверка только мандатных правил BLP (без ds-property)."""
        obj = self._get_object(object_name)
        sl  = subj.current_level   # subject level
        ol  = obj.level            # object level

        if mode == AccessMode.READ:
            # ss-property: No Read Up — субъект читает только если sl >= ol
            if sl >= ol:
                return AccessResult(
                    True,
                    f"ss-property OK: субъект [{sl}] >= объект [{ol}]."
                )
            else:
                return AccessResult(
                    False,
                    f"ss-property НАРУШЕНО (No Read Up): "
                    f"субъект [{sl}] < объект [{ol}]."
                )

        elif mode == AccessMode.WRITE:
            # *-property: No Write Down — субъект пишет только если ol >= sl
            if ol >= sl:
                return AccessResult(
                    True,
                    f"*-property OK: объект [{ol}] >= субъект [{sl}]."
                )
            else:
                return AccessResult(
                    False,
                    f"*-property НАРУШЕНО (No Write Down): "
                    f"объект [{ol}] < субъект [{sl}]."
                )

        elif mode == AccessMode.EXECUTE:
            # Исполнение регулируется только дискреционно (ds-property уже проверено)
            return AccessResult(True, "execute: только ds-property.")

        return AccessResult(False, f"Неизвестный режим доступа: {mode}.")

    def _get_subject(self, name: str) -> Subject:
        if name not in self.subjects:
            raise KeyError(f"Субъект '{name}' не найден в системе.")
        return self.subjects[name]

    def _get_object(self, name: str) -> Object:
        if name not in self.objects:
            raise KeyError(f"Объект '{name}' не найден в системе.")
        return self.objects[name]

    def _log_event(self, message: str) -> None:
        self._log.append(message)


# ─────────────────────────────────────────────
# 6. Демонстрационный сценарий
# ─────────────────────────────────────────────

def demo() -> None:
    print("=" * 60)
    print("  Модель Белла-ЛаПадулы — Демонстрация")
    print("=" * 60)

    # ── Создаём систему ────────────────────────
    blp = BellLaPadulaSystem("ИС 'Архив'")

    # ── Субъекты ───────────────────────────────
    alice = Subject(
        name="Alice",
        max_level=Level.SECRET,
        current_level=Level.CONFIDENTIAL,
    )
    bob = Subject(
        name="Bob",
        max_level=Level.TOP_SECRET,
        current_level=Level.SECRET,
    )
    charlie = Subject(
        name="Charlie",
        max_level=Level.CONFIDENTIAL,
        current_level=Level.UNCLASSIFIED,
    )

    # ── Объекты ───────────────────────────────
    doc_low  = Object("doc_low",    Level.UNCLASSIFIED, "Публичный отчёт 2024")
    doc_conf = Object("doc_conf",   Level.CONFIDENTIAL, "Конфиденц. инструкция")
    doc_sec  = Object("doc_sec",    Level.SECRET,       "Секретный приказ №7")
    doc_ts   = Object("doc_ts",     Level.TOP_SECRET,   "Сов.секретный план 'Гром'")

    for entity in [alice, bob, charlie]:
        blp.add_subject(entity)
    for obj in [doc_low, doc_conf, doc_sec, doc_ts]:
        blp.add_object(obj)

    # ── Дискреционные права (ACL) ──────────────
    blp.grant_discretionary("Alice",   "doc_low",  {AccessMode.READ, AccessMode.WRITE})
    blp.grant_discretionary("Alice",   "doc_conf", {AccessMode.READ, AccessMode.WRITE})
    blp.grant_discretionary("Alice",   "doc_sec",  {AccessMode.READ, AccessMode.WRITE})
    blp.grant_discretionary("Bob",     "doc_conf", {AccessMode.READ})
    blp.grant_discretionary("Bob",     "doc_sec",  {AccessMode.READ, AccessMode.WRITE})
    blp.grant_discretionary("Bob",     "doc_ts",   {AccessMode.READ, AccessMode.WRITE})
    blp.grant_discretionary("Charlie", "doc_low",  {AccessMode.READ})
    blp.grant_discretionary("Charlie", "doc_conf", {AccessMode.READ, AccessMode.WRITE})

    blp.show_state()

    # ────────────────────────────────────────────
    print("\n\n◆ Сценарий 1: Базовые проверки доступа")
    print("─" * 60)

    tests = [
        # (субъект,   объект,       режим,              ожидание)
        ("Alice",   "doc_low",    AccessMode.READ,    "Разрешён — ss OK"),
        ("Alice",   "doc_conf",   AccessMode.READ,    "Разрешён — ss OK"),
        ("Alice",   "doc_sec",    AccessMode.READ,    "ОТКАЗ — current=CONF < obj=SEC (No Read Up)"),
        ("Alice",   "doc_low",    AccessMode.WRITE,   "Разрешён — * OK"),
        ("Alice",   "doc_conf",   AccessMode.WRITE,   "Разрешён — * OK"),
        ("Alice",   "doc_sec",    AccessMode.WRITE,   "Разрешён — * OK (obj >= subj)"),
        ("Bob",     "doc_sec",    AccessMode.READ,    "Разрешён — ss OK"),
        ("Bob",     "doc_ts",     AccessMode.READ,    "Разрешён — ss OK"),
        ("Bob",     "doc_conf",   AccessMode.WRITE,   "ОТКАЗ — * НАРУШЕНО (No Write Down)"),
        ("Charlie", "doc_conf",   AccessMode.READ,    "ОТКАЗ — ss НАРУШЕНО (No Read Up)"),
        ("Charlie", "doc_low",    AccessMode.READ,    "Разрешён — ss OK"),
        ("Charlie", "doc_conf",   AccessMode.WRITE,   "Разрешён — * OK"),
    ]

    for subj_name, obj_name, mode, comment in tests:
        r = blp.request_access(subj_name, obj_name, mode)
        icon = "✓" if r.granted else "✗"
        print(f"  {icon} {subj_name:8} [{mode.value:7}] -> {obj_name:10}  | {comment}")

    # ────────────────────────────────────────────
    print("\n\n◆ Сценарий 2: Alice повышает уровень до SECRET")
    print("─" * 60)

    # Предварительно создадим активные доступы Alice
    # (используем прямое добавление, чтобы показать отзыв при смене уровня)
    blp.subjects["Alice"].active_accesses = [
        ("doc_low",  AccessMode.READ),    # OK при новом уровне
        ("doc_conf", AccessMode.WRITE),   # OK при новом уровне
        ("doc_low",  AccessMode.WRITE),   # нарушает *-property при SECRET (ol=0 < sl=2)
    ]
    print("  Активные доступы Alice до изменения уровня:")
    for acc in blp.subjects["Alice"].active_accesses:
        print(f"    [{acc[1].value}] на '{acc[0]}'")

    revoked = blp.change_subject_level("Alice", Level.SECRET)

    print(f"\n  Alice: уровень поднят до {Level.SECRET}")
    if revoked:
        print("  Отозванные доступы:")
        for r in revoked:
            print(r)
    else:
        print("  Отозванных доступов нет.")

    print("\n  Активные доступы Alice ПОСЛЕ изменения уровня:")
    for acc in blp.subjects["Alice"].active_accesses:
        print(f"    [{acc[1].value}] на '{acc[0]}'")

    # ────────────────────────────────────────────
    print("\n\n◆ Сценарий 3: Alice понижает уровень обратно до CONFIDENTIAL")
    print("─" * 60)

    # Активные доступы после повышения — добавим доступы на высокий уровень
    blp.subjects["Alice"].active_accesses += [
        ("doc_sec",  AccessMode.READ),    # ol=2 >= sl=2 — OK при SECRET, но при CONF нет
        ("doc_sec",  AccessMode.WRITE),   # ol=2 >= sl=2 — OK при SECRET
    ]
    print("  Активные доступы Alice до понижения уровня:")
    for acc in blp.subjects["Alice"].active_accesses:
        print(f"    [{acc[1].value}] на '{acc[0]}'")

    revoked = blp.change_subject_level("Alice", Level.CONFIDENTIAL)

    print(f"\n  Alice: уровень снижен до {Level.CONFIDENTIAL}")
    if revoked:
        print("  Отозванные доступы:")
        for r in revoked:
            print(r)
    else:
        print("  Отозванных доступов нет.")

    print("\n  Активные доступы Alice ПОСЛЕ понижения уровня:")
    for acc in blp.subjects["Alice"].active_accesses:
        print(f"    [{acc[1].value}] на '{acc[0]}'")

    # ────────────────────────────────────────────
    print("\n\n◆ Сценарий 4: Чтение и запись данных через API системы")
    print("─" * 60)

    blp.subjects["Alice"].active_accesses.clear()

    # Bob читает секретный документ
    content = blp.read_object("Bob", "doc_sec")
    if content:
        print(f"  Bob прочитал 'doc_sec': '{content}'")

    # Bob пытается записать в конфиденциальный документ (нарушение *)
    ok = blp.write_object("Bob", "doc_conf", "Попытка записи вниз")
    print(f"  Bob записал в 'doc_conf': {'ДА' if ok else 'НЕТ (No Write Down)'}")

    # Bob записывает в секретный документ (разрешено)
    ok = blp.write_object("Bob", "doc_sec", "Обновлённый секретный приказ №7")
    print(f"  Bob записал в 'doc_sec': {'ДА' if ok else 'НЕТ'}")

    # ────────────────────────────────────────────
    print("\n\n◆ Сценарий 5: Попытка установить уровень выше max_level")
    print("─" * 60)
    try:
        blp.change_subject_level("Charlie", Level.SECRET)
    except ValueError as e:
        print(f"  Ошибка (ожидаема): {e}")

    # ── Итоговое состояние ─────────────────────
    blp.show_state()
    blp.show_log()


# ─────────────────────────────────────────────
# 7. Точка входа
# ─────────────────────────────────────────────

if __name__ == "__main__":
    demo()