import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QComboBox, QDateEdit, QTableWidget, QTableWidgetItem,
    QPushButton, QMessageBox, QFileDialog, QGroupBox
)
from PyQt5.QtCore import QDate, QStandardPaths, Qt
import os
import csv

# PRODUCT CLASS 
class Product:
    def __init__(self, title, author, grade_level, program,
                 subject, date_validated, category, remarks):
        self.title = title
        self.author = author
        self.grade_level = grade_level
        self.program = program
        self.subject = subject
        self.date_validated = date_validated
        self.category = category
        self.remarks = remarks

# FILE SAVE 
def save_to_csv(products, filename):
    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            "Title", "Author/Writer", "Grade Level",
            "Program", "Subject", "Date Validated",
            "Category", "Remarks"
        ])
        for p in products:
            writer.writerow([
                p.title, p.author, p.grade_level, p.program,
                p.subject, p.date_validated, p.category, p.remarks
            ])

#  FILE LOAD 
def load_from_csv(filename):
    products = []
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as file:
            reader = csv.reader(file)
            next(reader, None)
            for row in reader:
                if len(row) < 8:
                    continue
                products.append(Product(*row))
    return products

# AUTO FILENAME 
def get_next_filename():
    path = QStandardPaths.writableLocation(QStandardPaths.DocumentsLocation)
    i = 1
    while True:
        name = os.path.join(path, f"educational_inventory{i}.csv")
        if not os.path.exists(name):
            return name
        i += 1

#  MAIN APP 
def main():
    app = QApplication(sys.argv)
    window = QWidget()
    window.setWindowTitle("Leaning Resources Inventory")
    window.resize(1200, 720)

    main_layout = QHBoxLayout(window)

    # UNDO / REDO HISTORY
    undo_stack = []
    redo_stack = []

    def snapshot():
        """Take full state snapshot."""
        state = []
        for p in products:
            state.append(Product(
                p.title, p.author, p.grade_level, p.program,
                p.subject, p.date_validated, p.category, p.remarks
            ))
        return state

    def load_snapshot(state):
        """Load a saved snapshot to table."""
        products.clear()
        table.setRowCount(0)

        for p in state:
            products.append(p)
            r = table.rowCount()
            table.insertRow(r)
            table.setItem(r, 0, QTableWidgetItem(p.title))
            table.setItem(r, 1, QTableWidgetItem(p.author))
            table.setItem(r, 2, QTableWidgetItem(p.grade_level))
            table.setItem(r, 3, QTableWidgetItem(p.program))
            table.setItem(r, 4, QTableWidgetItem(p.subject))
            table.setItem(r, 5, QTableWidgetItem(p.date_validated))
            table.setItem(r, 6, QTableWidgetItem(p.category))
            table.setItem(r, 7, QTableWidgetItem(p.remarks))

    #  LEFT PANEL 
    form_group = QGroupBox("Add New Item")
    form_layout = QFormLayout()
    form_group.setLayout(form_layout)

    form_group.setStyleSheet("""
        QGroupBox {
            border: 2px solid #0078D4;
            border-radius: 8px;
            padding: 12px;
            font-weight: bold;
            font-size: 14px;
        }
    """)

    input_style = """
        QLineEdit, QComboBox, QDateEdit {
            padding: 8px;
            border: 1px solid #C3C3C3;
            border-radius: 6px;
            font-size: 14px;
        }
        QLineEdit:focus, QComboBox:focus, QDateEdit:focus {
            border: 2px solid #0078D4;
        }
    """

    # Inputs
    title_edit = QLineEdit();           title_edit.setStyleSheet(input_style)
    author_edit = QLineEdit();          author_edit.setStyleSheet(input_style)
    grade_level_box = QComboBox();      grade_level_box.setStyleSheet(input_style)
    program_box = QComboBox();          program_box.setStyleSheet(input_style)
    subject_box = QComboBox();          subject_box.setStyleSheet(input_style)
    date_edit = QDateEdit();            date_edit.setStyleSheet(input_style)
    category_box = QComboBox();         category_box.setStyleSheet(input_style)
    remarks_edit = QLineEdit();         remarks_edit.setStyleSheet(input_style)

    grade_level_box.addItems(["K Stage 1", "K Stage 2", "K Stage 3", "K Stage 4"])
    program_box.addItems(["Alive", "IPED", "ADM", "ALS", "SNED", "DRRM", "HEALTH"])

    subject_box.addItems([
        "Filipino", "English", "Math", "Science", "Makabansa",
        "Araling Panlipunan", "Music", "Arts", "Physical Education",
        "Health", "GMRC/Values"
    ])

    date_edit.setCalendarPopup(True)
    date_edit.setDisplayFormat("yyyy-MM-dd")
    date_edit.setDate(QDate.currentDate())

    category_box.addItems([
        "Learning Mat", "LAST", "Quarter Test Questionnaire",
        "Story Books", "Instructional Materials",
        "Manipulative", "Intervention Materials", "Research"
    ])

    # Add to layout
    form_layout.addRow("Title:", title_edit)
    form_layout.addRow("Author:", author_edit)
    form_layout.addRow("Grade Level:", grade_level_box)
    form_layout.addRow("Program:", program_box)
    form_layout.addRow("Subject:", subject_box)
    form_layout.addRow("Date Validated:", date_edit)
    form_layout.addRow("Category:", category_box)
    form_layout.addRow("Remarks:", remarks_edit)

    # buttons Styles
    btn_style = """
        QPushButton {
            background-color: #0078D4;
            color: white;
            padding: 10px;
            border-radius: 6px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #005EA0;
        }
    """

    add_btn = QPushButton("Add Item")
    remove_btn = QPushButton("Remove Selected")
    save_btn = QPushButton("Save to CSV")
    open_btn = QPushButton("Open CSV")

    for btn in (add_btn, remove_btn, save_btn, open_btn):
        btn.setStyleSheet(btn_style)

    form_layout.addRow(add_btn)
    form_layout.addRow(remove_btn)
    form_layout.addRow(save_btn)
    form_layout.addRow(open_btn)

    main_layout.addWidget(form_group, 1)

    # RIGHT PANEL 
    right_panel = QVBoxLayout()

    #  MAO NI Search + Undo + Redo Row 
    search_row = QHBoxLayout()

    search_bar = QLineEdit()
    search_bar.setPlaceholderText("🔍 Search...")
    search_bar.setStyleSheet("""
        QLineEdit {
            padding: 10px;
            border-radius: 16px;
            border: 1px solid #BEBEBE;
            font-size: 14px;
            background: #FFFFFF;
        }
        QLineEdit:focus {
            border: 2px solid #0078D4;
        }
    """)

    undo_btn = QPushButton("⤺")
    redo_btn = QPushButton("⤻")

    icon_style = """
        QPushButton {
            background: #FFFFFF;
            border: 1px solid #BEBEBE;
            padding: 6px 12px;
            border-radius: 10px;
            font-size: 20px;
        }
        QPushButton:hover {
            background: #F0F0F0;
        }
    """

    undo_btn.setStyleSheet(icon_style)
    redo_btn.setStyleSheet(icon_style)

    search_row.addWidget(search_bar)
    search_row.addWidget(undo_btn)
    search_row.addWidget(redo_btn)

    right_panel.addLayout(search_row)

    #  TABLE 
    table = QTableWidget()
    table.setColumnCount(8)
    table.setHorizontalHeaderLabels([
        "Title", "Author/Writer", "Grade Level",
        "Program", "Subject", "Date Validated",
        "Category", "Remarks"
    ])
    table.setSortingEnabled(True)
    table.setAlternatingRowColors(True)

    table.setStyleSheet("""
        QHeaderView::section {
            background-color: #E5E5E5;
            padding: 8px;
            border: 1px solid #C0C0C0;
            font-weight: bold;
        }
        QTableWidget {
            gridline-color: #C0C0C0;
            font-size: 14px;
        }
    """)

    right_panel.addWidget(table)
    main_layout.addLayout(right_panel, 2)

    # Storage
    products = []

    #  FILTER 
    def filter_table():
        text = search_bar.text().lower()
        for row in range(table.rowCount()):
            match = any(
                table.item(row, col)
                and text in table.item(row, col).text().lower()
                for col in range(table.columnCount())
            )
            table.setRowHidden(row, not match)

    search_bar.textChanged.connect(filter_table)

    #  BUTTON ACTIONS 
    def add_item():
        undo_stack.append(snapshot())
        redo_stack.clear()

        product = Product(
            title_edit.text().strip(),
            author_edit.text().strip(),
            grade_level_box.currentText(),
            program_box.currentText(),
            subject_box.currentText(),
            date_edit.date().toString("yyyy-MM-dd"),
            category_box.currentText(),
            remarks_edit.text().strip()
        )

        products.append(product)

        row = table.rowCount()
        table.insertRow(row)
        table.setItem(row, 0, QTableWidgetItem(product.title))
        table.setItem(row, 1, QTableWidgetItem(product.author))
        table.setItem(row, 2, QTableWidgetItem(product.grade_level))
        table.setItem(row, 3, QTableWidgetItem(product.program))
        table.setItem(row, 4, QTableWidgetItem(product.subject))
        table.setItem(row, 5, QTableWidgetItem(product.date_validated))
        table.setItem(row, 6, QTableWidgetItem(product.category))
        table.setItem(row, 7, QTableWidgetItem(product.remarks))

        title_edit.clear()
        author_edit.clear()
        remarks_edit.clear()

    def remove_item():
        row = table.currentRow()
        if row == -1:
            QMessageBox.warning(window, "Error", "Select a row first")
            return

        undo_stack.append(snapshot())
        redo_stack.clear()

        products.pop(row)
        table.removeRow(row)

    def open_csv():
        file, _ = QFileDialog.getOpenFileName(window, "Open CSV", "", "CSV Files (*.csv)")
        if not file:
            return

        undo_stack.append(snapshot())
        redo_stack.clear()

        loaded = load_from_csv(file)
        load_snapshot(loaded)

    def save_csv():
        if not products:
            QMessageBox.warning(window, "No Data", "Nothing to save.")
            return

        filename = get_next_filename()
        save_to_csv(products, filename)
        QMessageBox.information(window, "Saved", f"Saved as:\n{filename}")

    def undo():
        if not undo_stack:
            return
        redo_stack.append(snapshot())
        state = undo_stack.pop()
        load_snapshot(state)

    def redo():
        if not redo_stack:
            return
        undo_stack.append(snapshot())
        state = redo_stack.pop()
        load_snapshot(state)

    undo_btn.clicked.connect(undo)
    redo_btn.clicked.connect(redo)
    add_btn.clicked.connect(add_item)
    remove_btn.clicked.connect(remove_item)
    save_btn.clicked.connect(save_csv)
    open_btn.clicked.connect(open_csv)

    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
