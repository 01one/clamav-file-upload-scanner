import os
import logging
import tempfile
import subprocess
import shutil
import json
import magic
import secrets
import hashlib
import re
import tornado.ioloop
import tornado.web
import tornado.httpserver
from tornado.options import define, options
from tornado.web import HTTPError
import time

define("port", default=8000, help="run on the given port", type=int)
define("upload_dir", default="uploads", help="directory to store uploaded files")
define("max_file_size", default=20 * 1024 * 1024, help="max file size (20MB)", type=int)
define("session_timeout", default=3600, help="session timeout in seconds", type=int)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

ALLOWED_TYPES = {
    'application/pdf': ['.pdf'],
    'application/msword': ['.doc'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
    'application/vnd.ms-excel': ['.xls'],
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
    'application/vnd.ms-powerpoint': ['.ppt'],
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
    'image/gif': ['.gif'],
    'application/zip': ['.zip'],
    'application/x-7z-compressed': ['.7z'],
    'application/vnd.android.package-archive': ['.apk']
}

class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("X-XSS-Protection", "1; mode=block")
        self.set_header("X-Frame-Options", "DENY")
        self.set_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "img-src 'self' data:"
        )
        self.set_header("Referrer-Policy", "same-origin")
        self.set_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.set_header("Pragma", "no-cache")

    def get_current_user(self):
        return self.get_secure_cookie("user_id")

    def get_user_id(self):
        if not self.current_user:
            user_id = secrets.token_hex(16)
            self.set_secure_cookie("user_id", user_id, expires_days=1)
            return user_id
        return self.current_user.decode('utf-8')

    def options(self, *args, **kwargs):
        self.set_status(204)
        self.finish()

    def sanitize_filename(self, filename):
        filename = os.path.basename(filename)
        filename = re.sub(r'[^\w\.-]', '_', filename)
        return filename

class MainHandler(BaseHandler):
    def get(self):
        csrf_token = self.xsrf_token
        self.render("index.html", csrf_token=csrf_token)

class FileUploadHandler(BaseHandler):
    def post(self):
        try:
            self.check_xsrf_cookie()
        except:
            self.set_status(403)
            self.finish({"error": "Invalid CSRF token"})
            return

        if not os.path.exists(options.upload_dir):
            os.makedirs(options.upload_dir, mode=0o750)

        fileinfo = self.request.files.get('file', None)
        if not fileinfo:
            self.set_status(400)
            self.finish({"error": "No file provided"})
            return

        file_obj = fileinfo[0]
        original_filename = self.sanitize_filename(file_obj.filename)
        file_content = file_obj.body

        if len(file_content) > options.max_file_size:
            self.set_status(413)
            self.finish({"error": f"File too large. Maximum size: {options.max_file_size // (1024*1024)}MB"})
            return

        try:
            mime = magic.Magic(mime=True)
            file_type = mime.from_buffer(file_content)

            if file_type not in ALLOWED_TYPES:
                self.set_status(400)
                self.finish({"error": f"Invalid file type: {file_type}. Only supported formats are allowed."})
                return

            file_ext = os.path.splitext(original_filename.lower())[1]
            if file_ext not in ALLOWED_TYPES[file_type]:
                self.set_status(400)
                self.finish({"error": f"File extension doesn't match content type. Expected {ALLOWED_TYPES[file_type]} for {file_type}."})
                return

            temp_dir = tempfile.mkdtemp()
            temp_file_path = os.path.join(temp_dir, original_filename)

            try:
                with open(temp_file_path, 'wb') as f:
                    f.write(file_content)

                scan_result = self.scan_file(temp_file_path, file_type)

                if scan_result["safe"]:
                    unique_filename = f"{int(time.time())}_{original_filename}"
                    file_path = os.path.join(options.upload_dir, unique_filename)

                    with open(file_path, 'wb') as f:
                        f.write(file_content)

                    file_hash = hashlib.sha256(file_content).hexdigest()

                    logging.info(f"File saved: {unique_filename} ({file_hash})")
                    self.finish({
                        "success": True,
                        "filename": unique_filename,
                        "originalName": original_filename,
                        "fileHash": file_hash,
                        "scan_result": scan_result
                    })
                else:
                    self.set_status(400)
                    self.finish({
                        "error": "File scan failed",
                        "scan_result": scan_result
                    })
            finally:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)

        except Exception as e:
            logging.error(f"Error processing file: {str(e)}")
            self.set_status(500)
            self.finish({"error": "Internal server error"})

    def scan_file(self, file_path, file_type):
        scan_results = {
            "safe": True,
            "message": "File appears to be safe",
            "details": []
        }

        scan_completed = True
        has_clamav = self._check_clamav_available()

        if has_clamav:
            try:
                clamscan_command = [
                    'clamscan',
                    '--scan-pdf=yes',
                    '--max-filesize=20M',
                    '--max-scansize=20M',
                    '--max-recursion=5',
                    '--max-files=10',
                    file_path
                ]

                logging.info(f"Running ClamAV scan...")
                result = subprocess.run(
                    clamscan_command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=60,
                    text=True
                )

                if result.returncode == 1:
                    scan_results["safe"] = False
                    scan_results["message"] = "Malware detected"
                    scan_results["details"].append("ClamAV detected malware in the file")
                    logging.warning(f"ClamAV detected malware")
                    return scan_results
                elif result.returncode != 0:
                    scan_completed = False
                    scan_results["details"].append("ClamAV scan completed with warnings")
                    logging.warning(f"ClamAV scan warning")
                else:
                    scan_results["details"].append("ClamAV scan passed")

            except Exception as e:
                scan_completed = False
                logging.error(f"ClamAV scan error: {str(e)}")
                scan_results["details"].append(f"ClamAV scan error")
        else:
            scan_results["details"].append("ClamAV not available for virus scanning")

        if file_type == 'application/pdf':
            try:
                pdf_check = self._check_pdf_security(file_path)
                scan_results["details"].extend(pdf_check["details"])

                if not pdf_check["safe"]:
                    scan_results["safe"] = False
                    scan_results["message"] = pdf_check["message"]
                    return scan_results
            except Exception as e:
                scan_completed = False
                logging.error(f"PDF security check error: {str(e)}")
                scan_results["details"].append(f"PDF security check failed")

        if file_type in ['application/zip', 'application/x-7z-compressed']:
            try:
                archive_check = self._check_archive_security(file_path, file_type)
                scan_results["details"].extend(archive_check["details"])

                if not archive_check["safe"]:
                    scan_results["safe"] = False
                    scan_results["message"] = archive_check["message"]
                    return scan_results
            except Exception as e:
                scan_completed = False
                logging.error(f"Archive security check error: {str(e)}")
                scan_results["details"].append(f"Archive security check failed")

        if 'officedocument' in file_type or file_type == 'application/msword':
            try:
                office_check = self._check_office_security(file_path)
                scan_results["details"].extend(office_check["details"])

                if not office_check["safe"]:
                    scan_results["safe"] = False
                    scan_results["message"] = office_check["message"]
            except Exception as e:
                scan_completed = False
                logging.error(f"Office security check error: {str(e)}")
                scan_results["details"].append(f"Office security check failed")

        if not scan_completed:
            scan_results["safe"] = False
            scan_results["message"] = "File scan incomplete - security cannot be verified"

        return scan_results

    def _check_clamav_available(self):
        try:
            result = subprocess.run(
                ['clamscan', '--version'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def _check_pdf_security(self, file_path):
        result = {
            "safe": True,
            "message": "PDF appears safe",
            "details": ["PDF security check completed"]
        }

        try:
            with open(file_path, 'rb') as f:
                header = f.read(5000).lower()

            suspicious_patterns = [
                b'/js', b'/javascript', b'/launch', b'/action',
                b'/openaction', b'/acroform', b'/richmedia',
                b'/aamodel', b'/jbig2decode', b'/xfa'
            ]

            found_patterns = []
            for pattern in suspicious_patterns:
                if pattern in header:
                    found_patterns.append(pattern.decode('utf-8', errors='ignore'))

            if found_patterns:
                result["safe"] = False
                result["message"] = "PDF contains potentially unsafe elements"
                result["details"].append(f"Suspicious elements found: {', '.join(found_patterns)}")

        except Exception as e:
            logging.error(f"PDF security check error: {str(e)}")
            result["details"].append(f"PDF security check error")

        return result

    def _check_archive_security(self, file_path, file_type):
        result = {
            "safe": True,
            "message": "Archive appears safe",
            "details": ["Archive security check completed"]
        }

        try:
            if file_type == 'application/zip':
                import zipfile
                if zipfile.is_zipfile(file_path):
                    with zipfile.ZipFile(file_path) as zip_file:
                        for file_info in zip_file.infolist():
                            if file_info.filename.startswith('/') or '..' in file_info.filename:
                                result["safe"] = False
                                result["message"] = "Archive contains suspicious path traversal patterns"
                                result["details"].append(f"Suspicious path detected in archive")
                                return result

                            dangerous_exts = ['.exe', '.dll', '.js', '.vbs', '.bat', '.cmd', '.sh', '.ps1']
                            if any(file_info.filename.lower().endswith(ext) for ext in dangerous_exts):
                                result["details"].append(f"Archive contains potentially executable file")

                        if len(zip_file.namelist()) > 1000:
                            result["details"].append("Archive contains over 1000 files")

            elif file_type == 'application/x-7z-compressed':
                if os.path.getsize(file_path) > 50 * 1024 * 1024:
                    result["details"].append("Large archive file (>50MB)")

        except Exception as e:
            logging.error(f"Archive security check error: {str(e)}")
            result["details"].append(f"Archive security check error")

        return result

    def _check_office_security(self, file_path):
        result = {
            "safe": True,
            "message": "Document appears safe",
            "details": ["Document security check completed"]
        }

        try:
            with open(file_path, 'rb') as f:
                header = f.read(8000).lower()

            macro_patterns = [b'vba', b'macro', b'activex', b'document.write', b'autoopen', b'auto_open', b'autoclose']
            found_patterns = []

            for pattern in macro_patterns:
                if pattern in header:
                    found_patterns.append(pattern.decode('utf-8', errors='ignore'))

            if found_patterns:
                result["safe"] = False
                result["message"] = "Document contains potentially unsafe elements"
                result["details"].append(f"Document may contain macros or scripts")

        except Exception as e:
            logging.error(f"Office document security check error: {str(e)}")
            result["details"].append(f"Document security check error")

        return result



class FileListHandler(BaseHandler):
    def get(self):
        token = self.get_query_argument("_xsrf", None)
        if not token:
            self.set_status(403)
            self.finish({"error": "Invalid CSRF token"})
            return
        try:
            self.check_xsrf_cookie()
        except:
            self.set_status(403)
            self.finish({"error": "Invalid CSRF token"})
            return

        if not os.path.exists(options.upload_dir):
            os.makedirs(options.upload_dir, mode=0o750)

        files = []
        for filename in os.listdir(options.upload_dir):
            filepath = os.path.join(options.upload_dir, filename)
            if os.path.isfile(filepath):
                original_name = '_'.join(filename.split('_')[1:]) if '_' in filename else filename
                file_size = os.path.getsize(filepath)
                files.append({
                    "filename": filename,
                    "original_name": original_name,
                    "size": file_size,
                    "upload_time": int(filename.split('_')[0]) if '_' in filename else 0
                })

        self.set_header("Content-Type", "application/json")
        self.write({"files": files})

class FileDownloadHandler(BaseHandler):
    def get(self, filename):
        token = self.get_query_argument("_xsrf", None)
        if not token:
            self.set_status(403)
            self.finish({"error": "Invalid CSRF token"})
            return
        try:
            self.check_xsrf_cookie()
        except:
            self.set_status(403)
            self.finish({"error": "Invalid CSRF token"})
            return

        filename = self.sanitize_filename(filename)
        filepath = os.path.join(options.upload_dir, filename)

        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            self.set_status(404)
            self.finish({"error": "File not found"})
            return

        if not os.access(filepath, os.R_OK):
            self.set_status(403)
            self.finish({"error": "Access denied"})
            return

        mime = magic.Magic(mime=True)
        content_type = mime.from_file(filepath)

        self.set_header("Content-Type", content_type)
        self.set_header("Content-Disposition", f"attachment; filename={filename}")
        self.set_header("X-Content-Type-Options", "nosniff")

        with open(filepath, 'rb') as f:
            self.write(f.read())
        self.finish()

class FileDeleteHandler(BaseHandler):
    def delete(self, filename):
        token = self.get_query_argument("_xsrf", None)
        if not token:
            self.set_status(403)
            self.finish({"error": "Invalid CSRF token"})
            return
            
        try:
            self.check_xsrf_cookie()
        except:
            self.set_status(403)
            self.finish({"error": "Invalid CSRF token"})
            return

        filename = self.sanitize_filename(filename)
        filepath = os.path.join(options.upload_dir, filename)

        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            self.set_status(404)
            self.finish({"error": "File not found"})
            return

        try:
            os.remove(filepath)
            logging.info(f"File deleted: {filename}")
            self.finish({"success": True})
        except Exception as e:
            logging.error(f"Error deleting file: {str(e)}")
            self.set_status(500)
            self.finish({"error": "Internal server error"})

def make_app():
    static_path = os.path.join(os.path.dirname(__file__), "static")
    template_path = os.path.join(os.path.dirname(__file__), "templates")

    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/upload", FileUploadHandler),
        (r"/files", FileListHandler),
        (r"/download/(.*)", FileDownloadHandler),
        (r"/delete/(.*)", FileDeleteHandler),
        (r"/static/(.*)", tornado.web.StaticFileHandler, {"path": static_path}),
    ],
    template_path=template_path,
    static_path=static_path,
    cookie_secret=secrets.token_hex(32),
    xsrf_cookies=True,
    debug=True)

if __name__ == "__main__":
    tornado.options.parse_command_line()

    if not os.path.exists(options.upload_dir):
        os.makedirs(options.upload_dir, mode=0o750)

    app = make_app()
    http_server = tornado.httpserver.HTTPServer(
        app,
        xheaders=True,
        max_body_size=options.max_file_size + 1024
    )
    http_server.listen(options.port)

    logging.info(f"Server started on port {options.port}")
    logging.info(f"Upload directory: {options.upload_dir}")

    tornado.ioloop.IOLoop.current().start()
