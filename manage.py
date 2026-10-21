#!/usr/bin/env python3
"""
KyroMail - utilitaire d'administration en ligne de commande.

Commandes disponibles :
    python manage.py init-db [--force]
    python manage.py create-admin [--name ...] [--email ...] [--password ...]
    python manage.py list-users
    python manage.py reset-password --email <adresse>
    python manage.py set-role --email <adresse> --role <role>
    python manage.py toggle-user --email <adresse>

Les mots de passe saisis sont hachés avant enregistrement ; ils ne sont
jamais écrits en clair dans la base de données.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from app import (
    ROLES,
    app,
    create_user,
    db_label,
    execute,
    find_user_by_email,
    generate_password_hash,
    get_user,
    init_db,
    log_action,
    now_iso,
    query,
    tables_ready,
    validate_password,
)


def _ensure_db() -> None:
    if not tables_ready():
        raise ValueError(
            "Base de données introuvable. Exécutez d'abord : python manage.py init-db"
        )


def _prompt_password(confirm: bool = True) -> str:
    password = getpass.getpass("Mot de passe : ")
    if confirm:
        again = getpass.getpass("Confirmation du mot de passe : ")
        if password != again:
            raise ValueError("Les deux mots de passe ne correspondent pas.")
    errors = validate_password(password)
    if errors:
        raise ValueError(" ".join(errors))
    return password


def cmd_init_db(args) -> None:
    init_db(force=args.force)
    print(f"Base de données prête : {db_label()}")
    if args.force:
        print("Ancienne base supprimée puis recréée (--force).")


def cmd_create_admin(args) -> None:
    _ensure_db()
    with app.app_context():
        name = args.name or input("Nom complet : ").strip()
        email = args.email or input("Adresse mail : ").strip()
        password = args.password or _prompt_password()

        if args.password:
            errors = validate_password(password)
            if errors:
                raise ValueError(" ".join(errors))

        try:
            user_id = create_user(name, email, password, "admin", active=True)
        except ValueError:
            raise
        created = get_user(user_id)
        log_action(
            "Création d'administrateur (CLI)",
            f"{created['full_name']} <{created['email']}>",
            admin_id=user_id,
        )
        print("Compte administrateur créé :")
        print(f"  Nom     : {created['full_name']}")
        print(f"  Mail    : {created['email']}")
        print(f"  Rôle    : {ROLES[created['role']]}")
        print(f"  État    : {'actif' if created['active'] else 'inactif'}")


def cmd_list_users(args) -> None:
    _ensure_db()
    with app.app_context():
        rows = query("SELECT * FROM users ORDER BY role, full_name")
        if not rows:
            print("Aucun compte.")
            return
        print(f"{'ID':<4} {'Nom':<24} {'Adresse':<34} {'Rôle':<15} {'État':<8} Dernière connexion")
        print("-" * 110)
        for row in rows:
            state = "actif" if row["active"] else "inactif"
            last = row["last_login"] or "-"
            print(
                f"{row['id']:<4} {row['full_name'][:23]:<24} "
                f"{row['email'][:33]:<34} {ROLES[row['role']]:<15} {state:<8} {last}"
            )
        print(f"\n{len(rows)} compte(s) au total.")


def cmd_reset_password(args) -> None:
    _ensure_db()
    with app.app_context():
        user = find_user_by_email(args.email)
        if user is None:
            raise ValueError(f"Aucun compte avec l'adresse {args.email}")
        password = args.password or _prompt_password()
        if args.password:
            errors = validate_password(password)
            if errors:
                raise ValueError(" ".join(errors))
        execute(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
            (generate_password_hash(password), now_iso(), user["id"]),
        )
        log_action(
            "Réinitialisation de mot de passe (CLI)",
            f"{user['email']}",
            admin_id=user["id"],
        )
        print(f"Mot de passe réinitialisé pour {user['full_name']} <{user['email']}>.")


def cmd_set_role(args) -> None:
    _ensure_db()
    if args.role not in ROLES:
        raise ValueError(
            "Rôle invalide. Valeurs acceptées : " + ", ".join(ROLES.keys())
        )
    with app.app_context():
        user = find_user_by_email(args.email)
        if user is None:
            raise ValueError(f"Aucun compte avec l'adresse {args.email}")
        if (
            user["role"] == "admin"
            and args.role != "admin"
            and user["active"]
        ):
            row = query(
                "SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND active = 1 "
                "AND id <> ?",
                (user["id"],),
                one=True,
            )
            if int(row["c"]) == 0:
                raise ValueError("Impossible : ce compte est le dernier administrateur actif.")
        execute(
            "UPDATE users SET role = ?, updated_at = ? WHERE id = ?",
            (args.role, now_iso(), user["id"]),
        )
        log_action(
            "Changement de rôle (CLI)",
            f"{user['email']} -> {ROLES[args.role]}",
        )
        print(f"{user['full_name']} est désormais : {ROLES[args.role]}.")


def cmd_toggle_user(args) -> None:
    _ensure_db()
    with app.app_context():
        user = find_user_by_email(args.email)
        if user is None:
            raise ValueError(f"Aucun compte avec l'adresse {args.email}")
        new_state = 0 if user["active"] else 1
        if new_state == 0 and user["role"] == "admin":
            row = query(
                "SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND active = 1 "
                "AND id <> ?",
                (user["id"],),
                one=True,
            )
            if int(row["c"]) == 0:
                raise ValueError("Impossible : ce compte est le dernier administrateur actif.")
        execute(
            "UPDATE users SET active = ?, updated_at = ? WHERE id = ?",
            (new_state, now_iso(), user["id"]),
        )
        log_action(
            "Activation / désactivation (CLI)",
            f"{user['email']} -> {'actif' if new_state else 'inactif'}",
        )
        print(
            f"{user['full_name']} <{user['email']}> est désormais "
            f"{'actif' if new_state else 'désactivé'}."
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="manage.py",
        description="Administration de la messagerie KyroMail.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init-db", help="Crée la base de données SQLite.")
    p_init.add_argument(
        "--force",
        action="store_true",
        help="Supprime la base existante avant de la recréer (destructeur).",
    )
    p_init.set_defaults(func=cmd_init_db)

    p_admin = sub.add_parser("create-admin", help="Crée le premier compte administrateur.")
    p_admin.add_argument("--name", help="Nom complet de l'administrateur.")
    p_admin.add_argument("--email", help="Adresse mail interne.")
    p_admin.add_argument(
        "--password",
        help="Mot de passe (sinon demandé de façon masquée).",
    )
    p_admin.set_defaults(func=cmd_create_admin)

    p_list = sub.add_parser("list-users", help="Affiche la liste des comptes.")
    p_list.set_defaults(func=cmd_list_users)

    p_reset = sub.add_parser("reset-password", help="Réinitialise un mot de passe.")
    p_reset.add_argument("--email", required=True, help="Adresse du compte.")
    p_reset.add_argument("--password", help="Nouveau mot de passe (sinon demandé).")
    p_reset.set_defaults(func=cmd_reset_password)

    p_role = sub.add_parser("set-role", help="Change le rôle d'un compte.")
    p_role.add_argument("--email", required=True, help="Adresse du compte.")
    p_role.add_argument("--role", required=True, help=" | ".join(ROLES.keys()))
    p_role.set_defaults(func=cmd_set_role)

    p_toggle = sub.add_parser("toggle-user", help="Active ou désactive un compte.")
    p_toggle.add_argument("--email", required=True, help="Adresse du compte.")
    p_toggle.set_defaults(func=cmd_toggle_user)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except ValueError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
