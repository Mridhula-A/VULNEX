import tkinter as tk
from database.db_manager import initialize
from gui.dashboard import Dashboard

def main():
    initialize()
    root = tk.Tk()
    Dashboard(root)
    root.mainloop()

if __name__ == "__main__":
    main()
