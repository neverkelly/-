"""
Лабораторная работа №9
Модель управления доступом на основе ролей (Role Based Access Control, RBAC)

Реализовано:
- Объекты (Object): ресурсы системы
- Субъекты (User): пользователи системы
- Разрешения (Permission): право на операцию над объектом
- Роли (Role): именованный набор разрешений
- Иерархия ролей: роль-наследник включает все права родительской роли
- Назначение ролей пользователям (User-Role Assignment)
- Смена активной роли пользователя
- Проверка доступа (Access Check)
- Демонстрация через интерактивное меню
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import textwrap
import sys


# ─────────────────────────────────────────────────────────────────────────────
# Доменные типы
# ─────────────────────────────────────────────────────────────────────────────

class Operation:
    """Операции (права доступа), которые можно выполнить над объектом."""
    READ    = "read"
    WRITE   = "write"
    EXECUTE = "execute"
    DELETE  = "delete"
    ADMIN   = "admin"

    ALL = [READ, WRITE, EXECUTE, DELETE, ADMIN]


@dataclass(frozen=True)
class Resource:
    """Объект системы — ресурс, к которому контролируется доступ."""
    name: str
    description: str = ""

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Permission:
    """Разрешение = (объект, операция)."""
    resource: Resource
    operation: str

    def __str__(self) -> str:
        return f"{self.operation}:{self.resource.name}"


# ─────────────────────────────────────────────────────────────────────────────
# Роль и иерархия ролей
# ─────────────────────────────────────────────────────────────────────────────

class Role:
    """
    Роль — именованный набор разрешений с поддержкой иерархии.

    Иерархия задаётся полем `parent`: роль-наследник владеет
    всеми разрешениями родителя плюс собственными (транзитивно).
    """

    def __init__(self, name: str, description: str = "",
                 parent: Optional["Role"] = None) -> None:
        self.name        = name
        self.description = description
        self.parent      = parent                    # прямой родитель
        self._own_perms: set[Permission] = set()     # собственные права

    # ── изменение ──────────────────────────────────────────────────────────

    def grant(self, *permissions: Permission) -> "Role":
        """Добавить разрешения непосредственно в эту роль."""
        self._own_perms.update(permissions)
        return self

    def revoke(self, *permissions: Permission) -> "Role":
        """Удалить разрешения из этой роли (не затрагивает родителей)."""
        self._own_perms -= set(permissions)
        return self

    # ── запросы ────────────────────────────────────────────────────────────

    @property
    def own_permissions(self) -> frozenset[Permission]:
        """Только собственные разрешения, без наследования."""
        return frozenset(self._own_perms)

    @property
    def effective_permissions(self) -> frozenset[Permission]:
        """Все действующие разрешения с учётом иерархии (BFS)."""
        collected: set[Permission] = set()
        visited:   set[str]        = set()
        queue = [self]
        while queue:
            role = queue.pop(0)
            if role.name in visited:
                continue
            visited.add(role.name)
            collected |= role._own_perms
            if role.parent:
                queue.append(role.parent)
        return frozenset(collected)

    def has_permission(self, resource: Resource, operation: str) -> bool:
        perm = Permission(resource, operation)
        return perm in self.effective_permissions

    def ancestor_chain(self) -> list["Role"]:
        """Список ролей от текущей до корня иерархии (включительно)."""
        chain, cur = [], self
        while cur:
            chain.append(cur)
            cur = cur.parent
        return chain

    # ── вспомогательное ────────────────────────────────────────────────────

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        parent_name = self.parent.name if self.parent else "—"
        return f"Role(name={self.name!r}, parent={parent_name!r})"


# ─────────────────────────────────────────────────────────────────────────────
# Пользователь
# ─────────────────────────────────────────────────────────────────────────────

class User:
    """
    Субъект системы.

    Пользователю может быть назначено несколько ролей, но единовременно
    активна только одна (принцип наименьших привилегий / least privilege).
    Пользователь может переключаться только между назначенными ему ролями.
    """

    def __init__(self, username: str) -> None:
        self.username    = username
        self._roles: set[Role]    = set()          # назначенные роли
        self._active_role: Optional[Role] = None   # текущая активная роль

    # ── управление ролями ──────────────────────────────────────────────────

    def assign_role(self, role: Role) -> None:
        """Назначить роль пользователю (администратором)."""
        self._roles.add(role)
        if self._active_role is None:
            self._active_role = role   # первая назначенная роль — активная

    def remove_role(self, role: Role) -> None:
        """Отозвать роль у пользователя."""
        self._roles.discard(role)
        if self._active_role is role:
            self._active_role = next(iter(self._roles), None)

    def switch_role(self, role: Role) -> None:
        """
        Сменить активную роль.
        Пользователь может активировать только ту роль, которая ему назначена.
        """
        if role not in self._roles:
            raise PermissionError(
                f"Пользователь '{self.username}' не имеет роли '{role.name}'."
            )
        self._active_role = role

    # ── запросы ────────────────────────────────────────────────────────────

    @property
    def assigned_roles(self) -> frozenset[Role]:
        return frozenset(self._roles)

    @property
    def active_role(self) -> Optional[Role]:
        return self._active_role

    def can(self, resource: Resource, operation: str) -> bool:
        """Проверить право доступа через *активную* роль."""
        if self._active_role is None:
            return False
        return self._active_role.has_permission(resource, operation)

    def __str__(self) -> str:
        return self.username

    def __repr__(self) -> str:
        active = self._active_role.name if self._active_role else "—"
        return f"User(username={self.username!r}, active_role={active!r})"


# ─────────────────────────────────────────────────────────────────────────────
# RBAC-система (реестр)
# ─────────────────────────────────────────────────────────────────────────────

class RBACSystem:
    """
    Центральный реестр RBAC.

    Хранит:
      - ресурсы  (объекты)
      - роли
      - пользователей (субъекты)
    и предоставляет единый интерфейс для управления и проверки доступа.
    """

    def __init__(self, name: str = "RBAC-система") -> None:
        self.name      = name
        self._resources: dict[str, Resource] = {}
        self._roles:     dict[str, Role]     = {}
        self._users:     dict[str, User]     = {}

    # ── ресурсы ────────────────────────────────────────────────────────────

    def add_resource(self, name: str, description: str = "") -> Resource:
        r = Resource(name, description)
        self._resources[name] = r
        return r

    def get_resource(self, name: str) -> Resource:
        return self._resources[name]

    # ── роли ───────────────────────────────────────────────────────────────

    def add_role(self, name: str, description: str = "",
                 parent: Optional[Role] = None) -> Role:
        role = Role(name, description, parent)
        self._roles[name] = role
        return role

    def get_role(self, name: str) -> Role:
        return self._roles[name]

    # ── пользователи ───────────────────────────────────────────────────────

    def add_user(self, username: str) -> User:
        u = User(username)
        self._users[username] = u
        return u

    def get_user(self, username: str) -> User:
        return self._users[username]

    # ── проверка доступа ───────────────────────────────────────────────────

    def check_access(self, username: str,
                     resource_name: str, operation: str) -> bool:
        """Вернуть True, если пользователю разрешена операция над ресурсом."""
        user     = self._users.get(username)
        resource = self._resources.get(resource_name)
        if user is None or resource is None:
            return False
        return user.can(resource, operation)

    # ── отчёты ─────────────────────────────────────────────────────────────

    def print_roles_report(self) -> None:
        sep = "─" * 70
        print(f"\n{'═'*70}")
        print(f"  {self.name}: Иерархия ролей и разрешения")
        print(f"{'═'*70}")
        for role in self._roles.values():
            chain = " → ".join(r.name for r in reversed(role.ancestor_chain()))
            print(f"\n  Роль: {role.name}")
            print(f"  Описание: {role.description or '—'}")
            print(f"  Цепочка наследования: {chain}")
            own  = sorted(str(p) for p in role.own_permissions)
            eff  = sorted(str(p) for p in role.effective_permissions)
            inh  = sorted(str(p) for p in
                          role.effective_permissions - role.own_permissions)
            print(f"  Собственные права ({len(own)}): "
                  f"{', '.join(own) or '(нет)'}")
            print(f"  Унаследованные права ({len(inh)}): "
                  f"{', '.join(inh) or '(нет)'}")
            print(f"  Все действующие права ({len(eff)}): "
                  f"{', '.join(eff) or '(нет)'}")
            print(f"  {sep}")

    def print_users_report(self) -> None:
        print(f"\n{'═'*70}")
        print(f"  {self.name}: Пользователи и роли")
        print(f"{'═'*70}")
        for user in self._users.values():
            roles_str  = ", ".join(r.name for r in user.assigned_roles) or "(нет)"
            active_str = user.active_role.name if user.active_role else "(нет)"
            print(f"\n  Пользователь: {user.username}")
            print(f"  Назначенные роли: {roles_str}")
            print(f"  Активная роль:    {active_str}")

    def print_access_matrix(self) -> None:
        """Матрица доступа: строки — пользователи, столбцы — (ресурс, операция)."""
        pairs = [(r, op)
                 for r in self._resources.values()
                 for op in Operation.ALL]
        # Отфильтруем только реально задействованные пары
        used_pairs = [p for p in pairs
                      if any(Permission(p[0], p[1]) in role.effective_permissions
                             for role in self._roles.values())]
        if not used_pairs:
            print("Нет ни одного разрешения в системе.")
            return

        col_w = 18
        header_cells = [f"{p[0].name}:{p[1]}"[:col_w].center(col_w)
                        for p in used_pairs]
        user_w = max(len(u) for u in self._users) + 2

        print(f"\n{'═'*70}")
        print(f"  Матрица доступа (активная роль каждого пользователя)")
        print(f"{'═'*70}")
        print(" " * user_w + "  " + "  ".join(header_cells))
        print(" " * user_w + "  " + "  ".join(["─" * col_w] * len(used_pairs)))

        for user in self._users.values():
            cells = []
            for (res, op) in used_pairs:
                allowed = user.can(res, op)
                cells.append(("  ✓  " if allowed else "  ✗  ").center(col_w))
            print(f"  {user.username:<{user_w}}" + "  ".join(cells))


# ─────────────────────────────────────────────────────────────────────────────
# Демонстрация
# ─────────────────────────────────────────────────────────────────────────────

def build_demo_system() -> RBACSystem:
    """
    Строит демонстрационную RBAC-систему для корпоративного портала.

    Иерархия ролей:
        Guest
          └── Employee          (наследует Guest)
                └── Manager     (наследует Employee)
                      └── Admin (наследует Manager)

    Ресурсы: публичная страница, документы, база данных, системные настройки.
    """
    rbac = RBACSystem("Корпоративный портал")

    # ── ресурсы ──────────────────────────────────────────────────────────
    public_page = rbac.add_resource("PublicPage",   "Публичная страница портала")
    documents   = rbac.add_resource("Documents",    "Внутренние документы компании")
    database    = rbac.add_resource("Database",     "Корпоративная база данных")
    sys_config  = rbac.add_resource("SysConfig",    "Системные настройки")
    audit_log   = rbac.add_resource("AuditLog",     "Журнал аудита")

    # ── роли (иерархия через parent) ─────────────────────────────────────
    guest = rbac.add_role(
        "Guest",
        "Гость: только чтение публичных страниц"
    )
    guest.grant(
        Permission(public_page, Operation.READ),
    )

    employee = rbac.add_role(
        "Employee",
        "Сотрудник: работа с внутренними документами",
        parent=guest         # ← наследует права Guest
    )
    employee.grant(
        Permission(documents, Operation.READ),
        Permission(documents, Operation.WRITE),
        Permission(database,  Operation.READ),
    )

    manager = rbac.add_role(
        "Manager",
        "Менеджер: расширенные права на документы и БД",
        parent=employee      # ← наследует права Employee (и Guest)
    )
    manager.grant(
        Permission(documents, Operation.DELETE),
        Permission(database,  Operation.WRITE),
        Permission(audit_log, Operation.READ),
    )

    admin = rbac.add_role(
        "Admin",
        "Администратор: полный доступ ко всей системе",
        parent=manager       # ← наследует права Manager (и выше)
    )
    admin.grant(
        Permission(sys_config, Operation.READ),
        Permission(sys_config, Operation.WRITE),
        Permission(sys_config, Operation.ADMIN),
        Permission(database,   Operation.DELETE),
        Permission(database,   Operation.ADMIN),
        Permission(audit_log,  Operation.WRITE),
        Permission(audit_log,  Operation.DELETE),
    )

    # ── пользователи ─────────────────────────────────────────────────────
    alice = rbac.add_user("alice")
    alice.assign_role(admin)
    alice.assign_role(employee)   # alice имеет несколько назначенных ролей

    bob = rbac.add_user("bob")
    bob.assign_role(manager)
    bob.assign_role(employee)

    carol = rbac.add_user("carol")
    carol.assign_role(employee)

    dave = rbac.add_user("dave")
    dave.assign_role(guest)

    return rbac


# ─────────────────────────────────────────────────────────────────────────────
# Интерактивное меню
# ─────────────────────────────────────────────────────────────────────────────

def interactive_menu(rbac: RBACSystem) -> None:
    """Простое текстовое меню для демонстрации RBAC."""
    menu = textwrap.dedent("""
    ╔══════════════════════════════════════════════════════════╗
    ║            RBAC — Меню демонстрации                      ║
    ╠══════════════════════════════════════════════════════════╣
    ║  1. Показать иерархию ролей и разрешения                 ║
    ║  2. Показать пользователей и назначенные роли            ║
    ║  3. Показать матрицу доступа                             ║
    ║  4. Проверить доступ пользователя к ресурсу              ║
    ║  5. Сменить активную роль пользователя                   ║
    ║  6. Назначить роль пользователю                          ║
    ║  7. Отозвать роль у пользователя                         ║
    ║  0. Выход                                                ║
    ╚══════════════════════════════════════════════════════════╝
    """)

    while True:
        print(menu)
        choice = input("Выберите действие: ").strip()

        if choice == "1":
            rbac.print_roles_report()

        elif choice == "2":
            rbac.print_users_report()

        elif choice == "3":
            rbac.print_access_matrix()

        elif choice == "4":
            username  = input("Имя пользователя: ").strip()
            resource  = input("Имя ресурса: ").strip()
            operation = input(f"Операция {Operation.ALL}: ").strip()
            result = rbac.check_access(username, resource, operation)
            verdict = "✅ РАЗРЕШЕНО" if result else "❌ ЗАПРЕЩЕНО"
            user = rbac._users.get(username)
            active = user.active_role.name if user and user.active_role else "—"
            print(f"\n  {verdict}: {username} [{active}] → {operation}:{resource}")

        elif choice == "5":
            username  = input("Имя пользователя: ").strip()
            role_name = input("Новая активная роль: ").strip()
            user = rbac._users.get(username)
            role = rbac._roles.get(role_name)
            if user is None:
                print(f"  Пользователь '{username}' не найден.")
            elif role is None:
                print(f"  Роль '{role_name}' не найдена.")
            else:
                try:
                    old_role = user.active_role.name if user.active_role else "—"
                    user.switch_role(role)
                    print(f"  ✅ {username}: роль изменена '{old_role}' → '{role_name}'")
                except PermissionError as e:
                    print(f"  ❌ Ошибка: {e}")

        elif choice == "6":
            username  = input("Имя пользователя: ").strip()
            role_name = input("Роль для назначения: ").strip()
            user = rbac._users.get(username)
            role = rbac._roles.get(role_name)
            if user is None:
                print(f"  Пользователь '{username}' не найден.")
            elif role is None:
                print(f"  Роль '{role_name}' не найдена.")
            else:
                user.assign_role(role)
                print(f"  ✅ Роль '{role_name}' назначена пользователю '{username}'.")

        elif choice == "7":
            username  = input("Имя пользователя: ").strip()
            role_name = input("Роль для отзыва: ").strip()
            user = rbac._users.get(username)
            role = rbac._roles.get(role_name)
            if user is None:
                print(f"  Пользователь '{username}' не найден.")
            elif role is None:
                print(f"  Роль '{role_name}' не найдена.")
            else:
                user.remove_role(role)
                print(f"  ✅ Роль '{role_name}' отозвана у пользователя '{username}'.")

        elif choice == "0":
            print("  Выход.")
            sys.exit(0)

        else:
            print("  Неверный выбор. Попробуйте снова.")


# ─────────────────────────────────────────────────────────────────────────────
# Автоматические тесты
# ─────────────────────────────────────────────────────────────────────────────

def run_tests(rbac: RBACSystem) -> None:
    """Набор проверок корректности модели RBAC."""
    print("\n" + "═"*70)
    print("  Автоматические тесты")
    print("═"*70)

    passed = 0
    failed = 0

    def check(label: str, condition: bool) -> None:
        nonlocal passed, failed
        status = "✅ PASS" if condition else "❌ FAIL"
        print(f"  {status}  {label}")
        if condition:
            passed += 1
        else:
            failed += 1

    # Вспомогательные объекты
    guest_role    = rbac.get_role("Guest")
    employee_role = rbac.get_role("Employee")
    manager_role  = rbac.get_role("Manager")
    admin_role    = rbac.get_role("Admin")

    public_page   = rbac.get_resource("PublicPage")
    documents     = rbac.get_resource("Documents")
    database      = rbac.get_resource("Database")
    sys_config    = rbac.get_resource("SysConfig")
    audit_log     = rbac.get_resource("AuditLog")

    alice = rbac.get_user("alice")
    bob   = rbac.get_user("bob")
    carol = rbac.get_user("carol")
    dave  = rbac.get_user("dave")

    # ── Тест 1: Права Guest ──────────────────────────────────────────────
    check("Guest может читать PublicPage",
          guest_role.has_permission(public_page, Operation.READ))
    check("Guest НЕ может читать Documents",
          not guest_role.has_permission(documents, Operation.READ))

    # ── Тест 2: Наследование Employee ← Guest ────────────────────────────
    check("Employee наследует чтение PublicPage от Guest",
          employee_role.has_permission(public_page, Operation.READ))
    check("Employee может читать Documents (собственное право)",
          employee_role.has_permission(documents, Operation.READ))
    check("Employee НЕ может удалять Documents",
          not employee_role.has_permission(documents, Operation.DELETE))

    # ── Тест 3: Наследование Manager ← Employee ← Guest ──────────────────
    check("Manager наследует чтение PublicPage",
          manager_role.has_permission(public_page, Operation.READ))
    check("Manager наследует чтение Documents",
          manager_role.has_permission(documents, Operation.READ))
    check("Manager может удалять Documents (собственное право)",
          manager_role.has_permission(documents, Operation.DELETE))
    check("Manager НЕ может изменять SysConfig",
          not manager_role.has_permission(sys_config, Operation.WRITE))

    # ── Тест 4: Наследование Admin ← Manager ← Employee ← Guest ─────────
    check("Admin наследует все права Manager",
          all(p in admin_role.effective_permissions
              for p in manager_role.effective_permissions))
    check("Admin может изменять SysConfig (собственное право)",
          admin_role.has_permission(sys_config, Operation.WRITE))
    check("Admin может удалять Database",
          admin_role.has_permission(database, Operation.DELETE))

    # ── Тест 5: Активная роль пользователя (alice: Admin по умолчанию) ───
    check("alice (Admin) может изменять SysConfig",
          alice.can(sys_config, Operation.WRITE))
    check("alice (Admin) может удалять Database",
          alice.can(database, Operation.DELETE))

    # ── Тест 6: Смена активной роли ──────────────────────────────────────
    alice.switch_role(employee_role)
    check("alice переключилась на Employee — НЕ может изменять SysConfig",
          not alice.can(sys_config, Operation.WRITE))
    check("alice (Employee) может читать Documents",
          alice.can(documents, Operation.READ))

    # Переключение на недоступную роль должно вызывать исключение
    try:
        alice.switch_role(guest_role)     # Guest не назначен alice
        check("alice НЕ может активировать незначенную роль Guest", False)
    except PermissionError:
        check("PermissionError при попытке активировать неназначенную роль", True)

    # Вернём alice обратно в Admin
    alice.switch_role(admin_role)

    # ── Тест 7: dave (Guest) ──────────────────────────────────────────────
    check("dave (Guest) может читать PublicPage",
          dave.can(public_page, Operation.READ))
    check("dave (Guest) НЕ может читать Documents",
          not dave.can(documents, Operation.READ))
    check("dave (Guest) НЕ может читать Database",
          not dave.can(database, Operation.READ))

    # ── Тест 8: carol (Employee) ──────────────────────────────────────────
    check("carol (Employee) может читать Database",
          carol.can(database, Operation.READ))
    check("carol (Employee) НЕ может читать AuditLog",
          not carol.can(audit_log, Operation.READ))

    # ── Тест 9: bob (Manager) ─────────────────────────────────────────────
    check("bob (Manager) может читать AuditLog",
          bob.can(audit_log, Operation.READ))
    check("bob (Manager) может удалять Documents",
          bob.can(documents, Operation.DELETE))
    check("bob (Manager) НЕ может изменять SysConfig",
          not bob.can(sys_config, Operation.WRITE))

    # ── Итог ──────────────────────────────────────────────────────────────
    total = passed + failed
    print(f"\n  Итог: {passed}/{total} тестов пройдено", end="")
    if failed:
        print(f", {failed} провалено ❌")
    else:
        print("  🎉")
    print("═"*70)


# ─────────────────────────────────────────────────────────────────────────────
# Точка входа
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  Лабораторная работа №9 — Role Based Access Control      ║")
    print("╚══════════════════════════════════════════════════════════╝")

    rbac = build_demo_system()

    # Показать начальное состояние системы
    rbac.print_roles_report()
    rbac.print_users_report()
    rbac.print_access_matrix()

    # Запустить тесты
    run_tests(rbac)

    # Запустить интерактивное меню
    interactive_menu(rbac)


if __name__ == "__main__":
    main()
