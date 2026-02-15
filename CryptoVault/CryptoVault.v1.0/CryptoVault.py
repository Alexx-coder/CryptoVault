import sqlite3
from cryptography.fernet import Fernet 
from cryptography.hazmat.primitives import hashes
import base64 
import getpass
import secrets
import datetime
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SQLite3:
    def __init__(self):
        self.db_name = "CryptoVault.db"

    def init_database(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,         
            master_password_hash TEXT NOT NULL,      
            salt TEXT NOT NULL,                     
            vault_key_encrypted TEXT NOT NULL,       
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP                     
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,                
            website TEXT NOT NULL,                   
            website_url TEXT,                        
            username TEXT NOT NULL,                 
            encrypted_password TEXT NOT NULL,        
            category TEXT DEFAULT 'other',           
            notes TEXT,                              
            strength INTEGER DEFAULT 0,              
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP,                    
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,               
            ip_address TEXT,                         
            user_agent TEXT,                          
            status TEXT NOT NULL,                    
            details TEXT,                             
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS failed_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            attempt_count INTEGER DEFAULT 1,
            first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            locked_until TIMESTAMP,
            UNIQUE(username, ip_address)
        )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login)")


        cursor.execute("CREATE INDEX IF NOT EXISTS idx_passwords_user_id ON passwords(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_passwords_website ON passwords(website)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_passwords_category ON passwords(category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_passwords_created ON passwords(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_passwords_updated ON passwords(updated_at)")


        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_user_id ON security_logs(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON security_logs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_action ON security_logs(action_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_status ON security_logs(status)")


        cursor.execute("CREATE INDEX IF NOT EXISTS idx_failed_username ON failed_logins(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_failed_ip ON failed_logins(ip_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_failed_locked ON failed_logins(locked_until)")


        cursor.execute("CREATE INDEX IF NOT EXISTS idx_passwords_user_website ON passwords(user_id, website)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_user_time ON security_logs(user_id, timestamp)")

class Manager:
    def __init__(self):
        self.db = "CryptoVault.db"
        self.current_user_id = None
        self.current_fernet_key = None
        self.version = "v1.0"
        

    def _generate_fernet_key(self, password, salt):  
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key_material = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key_material)

    def registr(self):
        print("Добро пожаловать в отдел Регистрации!")

        username = input("Введите имя пользователю: ").strip()
        if not username:
            print("Имя не должно быть пустым!")
            return False
        
        conn = None
        try:
          conn = sqlite3.connect(self.db, timeout=30) 
          cursor = conn.cursor()
          cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
          if cursor.fetchone():
             print("Данный пользователь уже создан!")
             return False
             
          
        except Exception as CVE:
          print(f"Ошибка при проверке: {CVE}")
          return False
        finally:
            if conn:
                conn.close()
            

        
        while True:
            password = getpass.getpass("Придумайте мастер-пароль: ")
            confirm_password = getpass.getpass("Подтвердите мастер-пароль: ")

            if password != confirm_password:
                print("Пароли не совпадают! Повторите попытку.")
                continue
            elif len(password) < 8:
                print("Пароль слишком маленький! Повторите попытку.")
                continue
            else:
                break
        
        salt = secrets.token_bytes(32)
        password_hash = self._hash_password(password, salt)
        fernet_key = self._generate_fernet_key(password, salt) 

        conn = sqlite3.connect(self.db, timeout=30)
        cursor = conn.cursor()

        try:
            cursor.execute("""
            INSERT INTO users (username, master_password_hash, salt, vault_key_encrypted)
            VALUES (?, ?, ?, ?)
            """, (
                username,
                password_hash,
                base64.b64encode(salt).decode(),
                base64.b64encode(fernet_key).decode()
            ))
            
            user_id = cursor.lastrowid

            self.current_user_id = user_id
            self.current_fernet_key = fernet_key

            self._log_security(
                user_id=user_id,
                action_type="registration", 
                status="success",
                details=f"Зарегистрирован новый пользователь: {username}",
                ip_address="",      
                user_agent=""       
            )

            conn.commit()
            print("Регистрация успешна!")
            time.sleep(1)
            print(f"Добро пожаловать {username}")
            print("ВАЖНОЕ УВЕДОМЛЕНИЕ: Запомните свой мастер-пароль! Забыв его вы не сможете войти в аккаунт.")
            return True
        
        except sqlite3.OperationalError as CVS:
            if "locked" in str(CVS):
                print("Ошибка: База данных временно заблокирована. Попробуйте снова.")
            else:
                print(f"Ошибка базы данных: {CVS}")
            return False
        except Exception as CV:
            print(f"Возникла ошибка: {CV}")
            return False
        except KeyboardInterrupt as CVK:
            print("Программа приостановлена пользователем.")
        finally:
             if conn:
                conn.close()
   
            

    def login(self):
        print("Добро пожаловать в отдел Входа в аккаунт!")

        conn = sqlite3.connect(self.db, timeout=10)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
    
        if user_count == 0:
          print("В системе нет зарегистрированных пользователей!")
          print("Пожалуйста, сначала зарегистрируйтесь.")
          time.sleep(2)
          return False

        username = input("Введите логин аккаунт: ").strip()
        password = getpass.getpass("Введите теперь мастер-пароль: ").strip()

        conn = sqlite3.connect(self.db)
        cursor = conn.cursor()

        try:
            cursor.execute("""
            SELECT id, master_password_hash, salt, vault_key_encrypted
            FROM users WHERE username = ?
            """, (username,))

            user_data = cursor.fetchone()

            if not user_data:
                print("Данный пользователь не найден!")
                self._log_security(
                    user_id=0,
                    action_type="login_failed",
                    status="failed",
                    details=f"Попытка входа несуществующего пользователя: {username}"
                )
                return False
            
            user_id, stored_hash, salt_b64, key_b64 = user_data

            salt = base64.b64decode(salt_b64)
            password_hash = self._hash_password(password, salt)
            if password_hash != stored_hash:
                print("Неверный пароль!")
                self._log_security(
                    user_id=user_id,
                    action_type="login_failed",
                    status="failed",
                    details="Неверный мастер-пароль",
                    ip_address="",
                    user_agent=""
                )
                return False
            
            fernet_key = base64.b64decode(key_b64)

            cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", 
                         (datetime.datetime.now(), user_id))
            
            self.current_user_id = user_id
            self.current_fernet_key = fernet_key
            
            self._log_security(
                user_id=user_id,
                action_type="login_success",
                status="success",
                details="Успешный вход в систему"
            )
            
            conn.commit()
            print("Успешный вход в аккаунт!")
            print(f"Добро пожаловать {username}")
            return True
        
        except Exception as CV:
            print(f"Произошла ошибка: {CV}")
        except KeyboardInterrupt as CVK:
            print("Программа приостановлена пользователем.")
        finally:
            conn.close()




    def _hash_password(self, password, salt):
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.b64encode(kdf.derive(password.encode())).decode()
    
    def _log_security(self, user_id, action_type, status, details="", ip_address="", user_agent=""):
      conn = None  
      try:
        conn = sqlite3.connect(self.db)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT INTO security_logs (user_id, action_type, ip_address, user_agent, status, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, action_type, ip_address, user_agent, status, details))
        
        conn.commit()
      except Exception as CV:
          pass
      finally:
        if conn:  
            conn.close()  

    def _log_security_same_connection(self, cursor, user_id, action_type, status, details="", ip_address="", user_agent=""):
      try:
        cursor.execute("""
        INSERT INTO security_logs (user_id, action_type, ip_address, user_agent, status, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, action_type, ip_address, user_agent, status, details))
      except Exception as CV:
        print(f"Не удалось залогировать: {CV}")

    def is_logged_in(self):
        return self.current_user_id is not None and self.current_fernet_key is not None
    
    def logout(self):
        if self.current_user_id:
            self._log_security(
                user_id=self.current_user_id,
                action_type="logout",
                status="success",
                details="Пользователь вышел из системы"
            )
        
        self.current_user_id = None
        self.current_fernet_key = None
        print("Вы вышли из системы.")


class PasswordManager:
    def __init__(self, db, user_id, fernet_key):
        self.db = db
        self.user_id = user_id
        self.cipher = Fernet(fernet_key)
    
    def add_password(self, website, username, password, website_url="", category="other", notes=""):
        try:
            encrypted = self.cipher.encrypt(password.encode())
            
            conn = sqlite3.connect(self.db, timeout=10) 
            cursor = conn.cursor()
            
            cursor.execute("""
            INSERT INTO passwords (user_id, website, website_url, username, encrypted_password, category, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (self.user_id, website, website_url, username, base64.b64encode(encrypted).decode(), category, notes))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Ошибка: {e}")
            return False
        

    def show_passwords(self):
        try:
            conn = sqlite3.connect(self.db)
            cursor = conn.cursor()
            
            cursor.execute("""
            SELECT website, website_url, username, encrypted_password, category, notes
            FROM passwords WHERE user_id = ? ORDER BY website
            """, (self.user_id,))
            
            all_passwords = cursor.fetchall()
            conn.close()
            
            if not all_passwords:
                print("Ваш сейф пуст!")
                return
            
            for pwd in all_passwords:
                website, url, username, enc_password, category, notes = pwd
        
                encrypted = base64.b64decode(enc_password)
                decrypted = self.cipher.decrypt(encrypted).decode()
                
                print(f"\nСайт: {website}")
                if url and url != "-":
                    print(f"URL: {url}")
                    print(f"Логин: {username}")
                    print(f"Пароль: {decrypted}")
                    print(f"Категория: {category}")
                if notes and notes != "-":
                    print(f"Заметки: {notes}")

                
        except Exception as e:
            print(f"Ошибка при показе паролей: {e}")



class  MenuManager:
    def __init__(self):
        self.db = "CryptoVault.db"
        self.manager = Manager() 
        self.password_manager = None 

    def add_password(self):
        print("Хэширование пароля")

        

    def Menu(self):
        print("Привет! Я CryptoVault. Я тот кто хранит твои пароли в базе данных и оберегает их.")
        time.sleep(1)

        print("1 - ВХОД В АККАУНТ")
        print("2 - РЕГИСТРАЦИЯ")
        print("3 - ВЫХОД")
        while True:
            choice = input("Введите (1-3): ").strip()
            if choice == "1":
                time.sleep(1)
                if self.manager.login():
                    self.password_manager = PasswordManager(
                        self.db,
                        self.manager.current_user_id,
                        self.manager.current_fernet_key
                    )
                    self.show_menu()
            elif choice == "2":
                time.sleep(1)
                if self.manager.registr():
                    self.password_manager = PasswordManager(
                        self.db,
                        self.manager.current_user_id,
                        self.manager.current_fernet_key
                    )
                    self.show_menu()  
            elif choice == "3":
                return False
            else:
                print("Ваш ответ не понятен. Повторите попытку.")
                continue
    
    def create_info_password(self):
        print("Добро пожаловать в отдел создании информации пароля!")
        time.sleep(1)

        if not self.manager.is_logged_in():
            print("Произошла ошибка: Вы не вошли в систему")
            return


        while True:
            print("1 - Создать информацию")
            print("2 - Выход в меню")

            choice_path = input("Введите (1-2): ").strip()
            if choice_path == "1":
               
               create_info = input("Введите название приложение или путь к сайту : ").strip()
               if not create_info:
                 print("Данная строка не должна быть пустой!")
                 continue

               create_info_site = input("Введите URL-адрес сайта (необязательно): ").strip() or "-"
            
               create_login = input("Введите Логин аккаунта или Email: ").strip()

               user_password = getpass.getpass("Введите теперь пароль: ")
               confirm_password = getpass.getpass("Подтвердите пароль: ")
               if user_password != confirm_password:
                 print("Пароль не совпадает. Попробуйте снова")
                 continue

               category = input("Введите категорию сайта или приложения (необязательно): ").strip() or "-"

               notes = input("Напишите себе заметку (необязательно): ").strip() or "-"

               if self.password_manager:
                   success = self.password_manager.add_password(
                     website = create_info,          
                     website_url = create_info_site,  
                     username = create_login,         
                     password = user_password,        
                     category = category,
                     notes = notes
                   )
            
                   if success:
                     print("Данные успешно и безопасно сохранены")
                     print("Технология: Fernet AES-128")
                   else:
                     print("Ошибка при сохранении")
               else:
                  print("Ошибка: система паролей не загружена")
            
            elif choice_path == "2":
                print("Выхожу")
                break

            else:
                print("Не понятен ваш ответ. Повторите попытку")
                continue

    def show_all_passwords(self):
        if not self.manager.is_logged_in():
            print("Произошла ошибка: Вы не вошли в систему")
            return
        
        if not self.password_manager:
            print("Ошибка: система паролей не загружена")
            return
        
        print("Список ваших паролей:")
        self.password_manager.show_passwords()


    def generator_passwords(self):
      import string
      import random

      print("\nГенератор паролей")

      chars = string.ascii_letters + string.digits 
      password = ''.join(random.choice(chars) for _ in range(10))
    
      print("Ваш пароль сгенерирован:", password)

      while True:
          ещё = input("\nСгенерировать пароль ещё раз (да/нет): ").strip().lower()
          if ещё == "да":
              password = ''.join(random.choice(chars) for _ in range(10))
              print("Новый пароль сгенерирован:", password)
          elif ещё == "нет":
              print("Выхожу из данной функции")
            
              копировать = input("Скопировать последний пароль? (да/нет): ").strip().lower()
              if копировать == "да":
                  try:
                      import pyperclip
                      pyperclip.copy(password)
                      print("Пароль скопирован!")
                  except:
                      print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
            
              break
          else:
              print("Введите 'да' или 'нет'")


    def show_menu(self):
        print("Происходит переход в меню функций...")
        time.sleep(3)

        print("\nМеню Функций")

        print("1 - Создать информацию логина")
        print("2 - Просмотр информации логинов")
        print("3 - Генератор паролей")
        print("4 - Выход")

        while True:
            choice = input("Введите (1-4): ").strip()
            if choice == "1":
                print("Переход в функцию Создании информации логина...")
                time.sleep(2)
                self.create_info_password()
            elif choice == "2":
                print("Переход в функцию Просмотра информации логина")
                time.sleep(2)
                self.show_all_passwords()
            elif choice == "3":
                print("Переход в функцию Генератор паролей")
                time.sleep(2)
                self.generator_passwords()
            elif choice == "4":
                print("Выхожу...")
                time.sleep(1)
                return False
            else:
                print("Не понятен ваш ответ. Повторите попытку")
                continue
                




            
if __name__ == "__main__":
    try:
      print("Добро пожаловать в CryptoVault")

      db = SQLite3()
      db.init_database()

      app = MenuManager()
      app.Menu()

    except KeyboardInterrupt:
        print("\nБот остановлен пользователем")
    except Exception as CV:
        print(f"\n Возникла критическая ошибка: {CV}")
        import traceback
        traceback.print_exc()
    finally:
        print("\nCryptoVault завершает работу! До свидания!")


            

                
