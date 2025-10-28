import os
import time
import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding


class KeyManager:

    def __init__(self, key_storage_path: str = "keys"):
        self.key_storage_path = Path(key_storage_path)
        self.key_storage_path.mkdir(exist_ok=True)
        self.used_keys = self._load_used_keys()
        self.logger = logging.getLogger(__name__)

    def _load_used_keys(self) -> set:
        used_keys_file = self.key_storage_path / "used_keys.json"
        if used_keys_file.exists():
            with open(used_keys_file, 'r') as f:
                return set(json.load(f))
        return set()

    def _save_used_key(self, key_hash: str):
        self.used_keys.add(key_hash)
        used_keys_file = self.key_storage_path / "used_keys.json"
        with open(used_keys_file, 'w') as f:
            json.dump(list(self.used_keys), f)
    
    def generate_key(self, password: str, key_length: int = 32, 
                     iterations: int = 100000) -> Tuple[bytes, bytes]:
        
        if key_length not in [16, 24, 32]:
            raise ValueError("Довжина ключа має бути 16, 24 або 32 байти")
        
        salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode())
        
        
        key_hash = hashlib.sha256(key).hexdigest()
        if key_hash in self.used_keys:
            raise ValueError("Цей ключ вже використовувався! Згенеруйте новий.")
        
        self._save_used_key(key_hash)
        self.logger.info(f"Згенеровано новий ключ довжиною {key_length} байт")
        
        return key, salt
    
    def derive_key_from_salt(self, password: str, salt: bytes, 
                            key_length: int = 32, iterations: int = 100000) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def save_key_metadata(self, key_id: str, salt: bytes, metadata: Dict):
        key_file = self.key_storage_path / f"{key_id}.json"
        data = {
            "salt": salt.hex(),
            "created_at": datetime.now().isoformat(),
            "metadata": metadata
        }
        with open(key_file, 'w') as f:
            json.dump(data, f, indent=2)
        self.logger.info(f"Збережено метадані ключа: {key_id}")
    
    def load_key_metadata(self, key_id: str) -> Dict:
        key_file = self.key_storage_path / f"{key_id}.json"
        if not key_file.exists():
            raise FileNotFoundError(f"Ключ {key_id} не знайдено")
        
        with open(key_file, 'r') as f:
            data = json.load(f)
        data['salt'] = bytes.fromhex(data['salt'])
        return data


class CryptoEngine:
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.backend = default_backend()
    
    def encrypt_cbc(self, plaintext: bytes, key: bytes, 
                    block_size: int = 128) -> Dict[str, bytes]:
        
        iv = os.urandom(16)
        
        
        padder = sym_padding.PKCS7(block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(iv + ciphertext)
        mac = h.finalize()
        
        self.logger.info(f"CBC шифрування: {len(plaintext)} байт -> {len(ciphertext)} байт")
        
        return {
            'iv': iv,
            'ciphertext': ciphertext,
            'mac': mac,
            'mode': b'CBC'
        }
    
    def decrypt_cbc(self, encrypted_data: Dict[str, bytes], key: bytes,
                    block_size: int = 128) -> bytes:
        iv = encrypted_data['iv']
        ciphertext = encrypted_data['ciphertext']
        mac = encrypted_data['mac']
        
        h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(iv + ciphertext)
        try:
            h.verify(mac)
        except Exception as e:
            self.logger.error("HMAC перевірка не пройшла! Дані змінено!")
            raise ValueError("Дані були змінені або пошкоджені!")
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = sym_padding.PKCS7(block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        self.logger.info(f"CBC дешифрування: {len(ciphertext)} байт -> {len(plaintext)} байт")
        
        return plaintext
    
    def encrypt_gcm(self, plaintext: bytes, key: bytes) -> Dict[str, bytes]:
        nonce = os.urandom(12)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        tag = encryptor.tag
        
        self.logger.info(f"GCM шифрування: {len(plaintext)} байт -> {len(ciphertext)} байт")
        
        return {
            'nonce': nonce,
            'ciphertext': ciphertext,
            'tag': tag,
            'mode': b'GCM'
        }
    
    def decrypt_gcm(self, encrypted_data: Dict[str, bytes], key: bytes) -> bytes:
        nonce = encrypted_data['nonce']
        ciphertext = encrypted_data['ciphertext']
        tag = encrypted_data['tag']
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            self.logger.error("GCM тег не валідний! Дані змінено!")
            raise ValueError("Дані були змінені або пошкоджені!")
        
        self.logger.info(f"GCM дешифрування: {len(ciphertext)} байт -> {len(plaintext)} байт")
        
        return plaintext
    
    def encrypt_ctr(self, plaintext: bytes, key: bytes) -> Dict[str, bytes]:
        nonce = os.urandom(16)
        
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(nonce + ciphertext)
        mac = h.finalize()
        
        self.logger.info(f"CTR шифрування: {len(plaintext)} байт -> {len(ciphertext)} байт")
        
        return {
            'nonce': nonce,
            'ciphertext': ciphertext,
            'mac': mac,
            'mode': b'CTR'
        }
    
    def decrypt_ctr(self, encrypted_data: Dict[str, bytes], key: bytes) -> bytes:
        nonce = encrypted_data['nonce']
        ciphertext = encrypted_data['ciphertext']
        mac = encrypted_data['mac']
        
        h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(nonce + ciphertext)
        try:
            h.verify(mac)
        except Exception:
            self.logger.error("HMAC перевірка не пройшла в CTR режимі!")
            raise ValueError("Дані були змінені або пошкоджені!")
        
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        self.logger.info(f"CTR дешифрування: {len(ciphertext)} байт -> {len(plaintext)} байт")
        
        return plaintext


class PerformanceTester:
    
    def __init__(self):
        self.crypto = CryptoEngine()
        self.logger = logging.getLogger(__name__)
    
    def test_mode(self, mode: str, data: bytes, key: bytes) -> Dict:
        start = time.time()
        if mode == 'CBC':
            encrypted = self.crypto.encrypt_cbc(data, key)
        elif mode == 'GCM':
            encrypted = self.crypto.encrypt_gcm(data, key)
        elif mode == 'CTR':
            encrypted = self.crypto.encrypt_ctr(data, key)
        else:
            raise ValueError(f"Невідомий режим: {mode}")
        encrypt_time = time.time() - start
        
        start = time.time()
        if mode == 'CBC':
            decrypted = self.crypto.decrypt_cbc(encrypted, key)
        elif mode == 'GCM':
            decrypted = self.crypto.decrypt_gcm(encrypted, key)
        elif mode == 'CTR':
            decrypted = self.crypto.decrypt_ctr(encrypted, key)
        decrypt_time = time.time() - start
        
        assert data == decrypted, "Дешифровані дані не співпадають!"
        
        return {
            'mode': mode,
            'data_size': len(data),
            'encrypt_time': encrypt_time,
            'decrypt_time': decrypt_time,
            'total_time': encrypt_time + decrypt_time,
            'throughput_mbps': (len(data) / 1024 / 1024) / (encrypt_time + decrypt_time)
        }
    
    def run_benchmark(self, sizes: list = None) -> list:
        if sizes is None:
            sizes = [1024, 10*1024, 100*1024, 1024*1024, 10*1024*1024]  # 1KB to 10MB
        
        results = []
        key = os.urandom(32)
        
        for size in sizes:
            self.logger.info(f"\nТестування розміру: {size/1024:.2f} KB")
            data = os.urandom(size)
            
            for mode in ['CBC', 'GCM', 'CTR']:
                result = self.test_mode(mode, data, key)
                results.append(result)
                self.logger.info(
                    f"{mode}: шифр={result['encrypt_time']:.4f}s, "
                    f"дешифр={result['decrypt_time']:.4f}s, "
                    f"throughput={result['throughput_mbps']:.2f} MB/s"
                )
        
        return results
    
    def generate_report(self, results: list) -> str:
        report = "\n" + "="*80 + "\n"
        report += "ЗВІТ ПРО ПРОДУКТИВНІСТЬ РЕЖИМІВ ШИФРУВАННЯ AES\n"
        report += "="*80 + "\n\n"
        
        report += f"{'Режим':<10} {'Розмір':<15} {'Шифрування':<15} {'Дешифрування':<15} {'Throughput':<15}\n"
        report += "-"*80 + "\n"
        
        for r in results:
            report += f"{r['mode']:<10} "
            report += f"{r['data_size']/1024:.2f} KB{'':<7} "
            report += f"{r['encrypt_time']:.4f} s{'':<7} "
            report += f"{r['decrypt_time']:.4f} s{'':<7} "
            report += f"{r['throughput_mbps']:.2f} MB/s\n"
        
        report += "\n" + "="*80 + "\n"
        report += "ВИСНОВКИ:\n"
        report += "="*80 + "\n"
        report += "1. GCM режим: Найкраща опція для більшості застосувань.\n"
        report += "   - Забезпечує автентифікацію 'з коробки'\n"
        report += "   - Висока продуктивність\n"
        report += "   - Паралелізується\n\n"
        
        report += "2. CTR режим: Швидкий, але потребує окремої автентифікації.\n"
        report += "   - Можна паралелізувати\n"
        report += "   - Не потребує padding\n"
        report += "   - Необхідний HMAC для цілісності\n\n"
        
        report += "3. CBC режим: Традиційний, але повільніший.\n"
        report += "   - Не паралелізується\n"
        report += "   - Потребує padding\n"
        report += "   - Потребує окремого HMAC\n\n"
        
        return report


class CryptoApp:
    
    def __init__(self, storage_dir: str = "crypto_storage"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        
        self.key_manager = KeyManager(str(self.storage_dir / "keys"))
        self.crypto_engine = CryptoEngine()
        self.current_mode = 'GCM'
        self.current_key = None
        self.current_key_id = None
        
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
        self.logger.info("Криптографічний застосунок запущено")
    
    def _setup_logging(self):
        log_dir = self.storage_dir / "logs"
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"crypto_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
    
    def initialize_key(self, password: str, key_id: str, key_length: int = 32):
        try:
            key, salt = self.key_manager.generate_key(password, key_length)
            self.key_manager.save_key_metadata(key_id, salt, {
                'key_length': key_length,
                'algorithm': 'AES',
                'kdf': 'PBKDF2-SHA256'
            })
            
            self.current_key = key
            self.current_key_id = key_id
            
            self.logger.info(f"Ініціалізовано ключ: {key_id}")
            print(f"✓ Ключ '{key_id}' успішно створено")
            return True
        except Exception as e:
            self.logger.error(f"Помилка створення ключа: {e}")
            print(f"✗ Помилка: {e}")
            return False
    
    def load_key(self, password: str, key_id: str):
        try:
            metadata = self.key_manager.load_key_metadata(key_id)
            salt = metadata['salt']
            key_length = metadata['metadata']['key_length']
            
            key = self.key_manager.derive_key_from_salt(password, salt, key_length)
            
            self.current_key = key
            self.current_key_id = key_id
            
            self.logger.info(f"Завантажено ключ: {key_id}")
            print(f"✓ Ключ '{key_id}' успішно завантажено")
            return True
        except Exception as e:
            self.logger.error(f"Помилка завантаження ключа: {e}")
            print(f"✗ Помилка: {e}")
            return False
    
    def set_mode(self, mode: str):
        if mode.upper() not in ['CBC', 'GCM', 'CTR']:
            print(f"✗ Невідомий режим: {mode}")
            return False
        
        self.current_mode = mode.upper()
        self.logger.info(f"Режим змінено на: {self.current_mode}")
        print(f"✓ Режим шифрування: {self.current_mode}")
        return True
    
    def encrypt_file(self, input_file: str, output_file: Optional[str] = None):
        if self.current_key is None:
            print("✗ Спочатку завантажте або створіть ключ!")
            return False
        
        try:
            input_path = Path(input_file)
            if not input_path.exists():
                raise FileNotFoundError(f"Файл не знайдено: {input_file}")
            
            with open(input_path, 'rb') as f:
                plaintext = f.read()
            
            self.logger.info(f"Шифрування файлу: {input_file} ({len(plaintext)} байт)")
            
            if self.current_mode == 'CBC':
                encrypted_data = self.crypto_engine.encrypt_cbc(plaintext, self.current_key)
            elif self.current_mode == 'GCM':
                encrypted_data = self.crypto_engine.encrypt_gcm(plaintext, self.current_key)
            elif self.current_mode == 'CTR':
                encrypted_data = self.crypto_engine.encrypt_ctr(plaintext, self.current_key)
            
            if output_file is None:
                output_file = str(input_path) + '.encrypted'
            
            self._save_encrypted_file(output_file, encrypted_data)
            
            self.logger.info(f"Файл зашифровано: {output_file}")
            print(f"✓ Файл зашифровано: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Помилка шифрування: {e}", exc_info=True)
            print(f"✗ Помилка шифрування: {e}")
            return False
    
    def decrypt_file(self, input_file: str, output_file: Optional[str] = None):
        if self.current_key is None:
            print("✗ Спочатку завантажте ключ!")
            return False
        
        try:
            encrypted_data = self._load_encrypted_file(input_file)
            
            mode = encrypted_data['mode'].decode('utf-8')
            self.logger.info(f"Дешифрування файлу: {input_file} (режим: {mode})")
            
            if mode == 'CBC':
                plaintext = self.crypto_engine.decrypt_cbc(encrypted_data, self.current_key)
            elif mode == 'GCM':
                plaintext = self.crypto_engine.decrypt_gcm(encrypted_data, self.current_key)
            elif mode == 'CTR':
                plaintext = self.crypto_engine.decrypt_ctr(encrypted_data, self.current_key)
            
            if output_file is None:
                output_file = input_file.replace('.encrypted', '.decrypted')
            
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
            self.logger.info(f"Файл дешифровано: {output_file}")
            print(f"✓ Файл дешифровано: {output_file}")
            return True
            
        except ValueError as e:
            self.logger.error(f"КРИТИЧНА ПОМИЛКА: {e}")
            print(f"✗ КРИТИЧНА ПОМИЛКА: {e}")
            print("  Можлива спроба підміни даних або неправильний ключ!")
            return False
        except Exception as e:
            self.logger.error(f"Помилка дешифрування: {e}", exc_info=True)
            print(f"✗ Помилка дешифрування: {e}")
            return False
    
    def _save_encrypted_file(self, filename: str, encrypted_data: Dict[str, bytes]):
        with open(filename, 'wb') as f:
            f.write(encrypted_data['mode'])
            f.write(b'\n')
            
            if 'iv' in encrypted_data:
                f.write(b'IV:')
                f.write(encrypted_data['iv'])
            else:
                f.write(b'NONCE:')
                f.write(encrypted_data['nonce'])
            f.write(b'\n')
            
            if 'mac' in encrypted_data:
                f.write(b'MAC:')
                f.write(encrypted_data['mac'])
                f.write(b'\n')
            elif 'tag' in encrypted_data:
                f.write(b'TAG:')
                f.write(encrypted_data['tag'])
                f.write(b'\n')
            
            f.write(b'DATA:')
            f.write(encrypted_data['ciphertext'])
    
    def _load_encrypted_file(self, filename: str) -> Dict[str, bytes]:
        with open(filename, 'rb') as f:
            content = f.read()
        
        lines = content.split(b'\n')
        mode = lines[0]
        
        result = {'mode': mode}
        
        for line in lines[1:]:
            if line.startswith(b'IV:'):
                result['iv'] = line[3:]
            elif line.startswith(b'NONCE:'):
                result['nonce'] = line[6:]
            elif line.startswith(b'MAC:'):
                result['mac'] = line[4:]
            elif line.startswith(b'TAG:'):
                result['tag'] = line[4:]
            elif line.startswith(b'DATA:'):
                result['ciphertext'] = line[5:]
        
        return result
    
    def simulate_tampering(self, encrypted_file: str):
        self.logger.warning(f"СИМУЛЯЦІЯ АТАКИ: підміна файлу {encrypted_file}")
        print(f"\n⚠ СИМУЛЯЦІЯ АТАКИ: підміна даних у файлі {encrypted_file}")
        
        try:
            with open(encrypted_file, 'rb') as f:
                content = f.read()
            
            middle = len(content) // 2
            modified = content[:middle] + bytes([content[middle] ^ 0xFF]) + content[middle+1:]
            
            tampered_file = encrypted_file + '.tampered'
            with open(tampered_file, 'wb') as f:
                f.write(modified)
            
            self.logger.warning(f"Створено підроблений файл: {tampered_file}")
            print(f"✓ Створено підроблений файл: {tampered_file}")
            print(f"  Спробуйте дешифрувати його для перевірки виявлення підміни")
            
            return tampered_file
            
        except Exception as e:
            self.logger.error(f"Помилка симуляції: {e}")
            print(f"✗ Помилка: {e}")
            return None


def main():
    print("="*80)
    print("КРИПТОГРАФІЧНА СИСТЕМА AES")
    print("Підтримка режимів: CBC, GCM, CTR")
    print("="*80)
    
    app = CryptoApp()
    
    while True:
        print("\n" + "-"*80)
        print("ГОЛОВНЕ МЕНЮ:")
        print("1. Створити новий ключ")
        print("2. Завантажити існуючий ключ")
        print("3. Змінити режим шифрування (поточний: {})".format(app.current_mode))
        print("4. Зашифрувати файл")
        print("5. Дешифрувати файл")
        print("6. Запустити тест продуктивності")
        print("7. Симулювати атаку підміни даних")
        print("8. Переглянути логи")
        print("0. Вихід")
        print("-"*80)
        
        choice = input("\nВиберіть опцію: ").strip()
        
        if choice == '1':
            print("\n--- СТВОРЕННЯ НОВОГО КЛЮЧА ---")
            key_id = input("Введіть ідентифікатор ключа: ").strip()
            password = input("Введіть пароль для ключа: ").strip()
            key_length_input = input("Довжина ключа (16/24/32 байт, Enter=32): ").strip()
            key_length = int(key_length_input) if key_length_input else 32
            
            app.initialize_key(password, key_id, key_length)
        
        elif choice == '2':
            print("\n--- ЗАВАНТАЖЕННЯ КЛЮЧА ---")
            key_id = input("Введіть ідентифікатор ключа: ").strip()
            password = input("Введіть пароль: ").strip()
            
            app.load_key(password, key_id)
        
        elif choice == '3':
            print("\n--- ЗМІНА РЕЖИМУ ШИФРУВАННЯ ---")
            print("Доступні режими:")
            print("  CBC - Cipher Block Chaining (з HMAC)")
            print("  GCM - Galois/Counter Mode (authenticated encryption)")
            print("  CTR - Counter Mode (з HMAC)")
            mode = input("Виберіть режим (CBC/GCM/CTR): ").strip()
            
            app.set_mode(mode)
        
        elif choice == '4':
            print("\n--- ШИФРУВАННЯ ФАЙЛУ ---")
            input_file = input("Шлях до файлу для шифрування: ").strip()
            output_file = input("Шлях для збереження (Enter=авто): ").strip()
            output_file = output_file if output_file else None
            
            app.encrypt_file(input_file, output_file)
        
        elif choice == '5':
            print("\n--- ДЕШИФРУВАННЯ ФАЙЛУ ---")
            input_file = input("Шлях до зашифрованого файлу: ").strip()
            output_file = input("Шлях для збереження (Enter=авто): ").strip()
            output_file = output_file if output_file else None
            
            app.decrypt_file(input_file, output_file)
        
        elif choice == '6':
            print("\n--- ТЕСТ ПРОДУКТИВНОСТІ ---")
            print("Запуск benchmark для всіх режимів...")
            print("Це може зайняти деякий час...\n")
            
            tester = PerformanceTester()
            results = tester.run_benchmark()
            report = tester.generate_report(results)
            
            print(report)
            
            report_file = app.storage_dir / "logs" / f"performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n✓ Звіт збережено: {report_file}")
        
        elif choice == '7':
            print("\n--- СИМУЛЯЦІЯ АТАКИ ---")
            encrypted_file = input("Шлях до зашифрованого файлу: ").strip()
            
            tampered_file = app.simulate_tampering(encrypted_file)
            
            if tampered_file:
                print("\nСпроба дешифрувати підроблений файл...")
                app.decrypt_file(tampered_file, None)
        
        elif choice == '8':
            print("\n--- ПЕРЕГЛЯД ЛОГІВ ---")
            log_dir = app.storage_dir / "logs"
            log_files = sorted(log_dir.glob("*.log"), key=lambda x: x.stat().st_mtime, reverse=True)
            
            if not log_files:
                print("Логи відсутні")
            else:
                print(f"Останній лог-файл: {log_files[0].name}")
                print("\nОстанні 20 рядків:")
                print("-"*80)
                with open(log_files[0], 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for line in lines[-20:]:
                        print(line.rstrip())
                print("-"*80)
        
        elif choice == '0':
            print("\nДо побачення!")
            break
        
        else:
            print("✗ Невірна опція. Спробуйте ще раз.")


if __name__ == "__main__":
    main()
