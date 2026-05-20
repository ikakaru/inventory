import csv
import sys
from pathlib import Path

from portal_server import (
    CATEGORIES,
    GRADE_LEVELS,
    ITEM_STATUS_APPROVED,
    PROGRAMS,
    SUBJECTS,
    ROLE_MANAGER,
    create_user,
    get_connection,
    get_user_by_username,
    init_db,
    utc_now,
)


LEGACY_COLUMNS = [
    "Title",
    "Author/Writer",
    "Grade Level",
    "Program",
    "Subject",
    "Date Validated",
    "Category",
    "Remarks",
]


def normalize_row(row):
    title = (row.get("Title") or "").strip()
    author = (row.get("Author/Writer") or "").strip()
    grade_level = (row.get("Grade Level") or "").strip()
    program = (row.get("Program") or "").strip()
    subject = (row.get("Subject") or "").strip()
    date_validated = (row.get("Date Validated") or "").strip()
    category = (row.get("Category") or "").strip()
    remarks = (row.get("Remarks") or "").strip()

    if not title or not author:
        return None
    if grade_level not in GRADE_LEVELS:
        grade_level = GRADE_LEVELS[0]
    if program not in PROGRAMS:
        program = PROGRAMS[0]
    if subject not in SUBJECTS:
        subject = SUBJECTS[0]
    if category not in CATEGORIES:
        category = CATEGORIES[0]

    return {
        "title": title,
        "author": author,
        "grade_level": grade_level,
        "program": program,
        "subject": subject,
        "date_validated": date_validated or utc_now().split("T")[0],
        "category": category,
        "remarks": remarks,
    }


def import_csv(csv_path, username):
    init_db()
    source = Path(csv_path)
    if not source.exists():
        raise FileNotFoundError(f"CSV file not found: {source}")

    with get_connection() as connection:
        manager = get_user_by_username(connection, username)
        if not manager:
            raise ValueError(f"Portal user '{username}' does not exist.")
        if manager["role"] != ROLE_MANAGER:
            raise ValueError(f"Portal user '{username}' must be a manager account for import.")

        imported = 0
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            missing = [column for column in LEGACY_COLUMNS if column not in reader.fieldnames]
            if missing:
                raise ValueError(f"CSV is missing required columns: {', '.join(missing)}")

            for row in reader:
                normalized = normalize_row(row)
                if not normalized:
                    continue
                now = utc_now()
                connection.execute(
                    """
                    INSERT INTO inventory_items (
                        title, author, grade_level, program, subject, date_validated,
                        category, remarks, status, created_by, updated_by, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized["title"],
                        normalized["author"],
                        normalized["grade_level"],
                        normalized["program"],
                        normalized["subject"],
                        normalized["date_validated"],
                        normalized["category"],
                        normalized["remarks"],
                        ITEM_STATUS_APPROVED,
                        manager["id"],
                        manager["id"],
                        now,
                        now,
                    ),
                )
                imported += 1
        return imported


def main():
    if len(sys.argv) < 2:
        print("Usage: python import_legacy_csv.py <csv_path> [manager_username]")
        raise SystemExit(1)

    csv_path = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else "manager"
    count = import_csv(csv_path, username)
    print(f"Imported {count} legacy rows into the shared portal database.")


if __name__ == "__main__":
    main()
