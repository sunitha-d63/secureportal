# import logging
# import hashlib
# import random

# from django.shortcuts import render, redirect, get_object_or_404
# from django.http import HttpResponse
# from django.contrib import messages
# from django.contrib.auth import authenticate, login, logout
# from django.contrib.auth.decorators import login_required
# from django.contrib.auth.models import User
# from django.core.files.base import ContentFile
# from django.core.mail import send_mail

# from .forms import RegisterForm, ResetPasswordForm,UploadForm
# from .models import EncryptedFile, PasswordResetOTP
# from .encryption.aes import generate_aes_key, encrypt_bytes, decrypt_bytes
# from .encryption.rsa import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
# from .encryption.keywrap import wrap_private_key, unwrap_private_key

# logger = logging.getLogger(__name__)


# def index(request):
#     if request.user.is_authenticated:
#         return redirect('dashboard')
#     return render(request, 'login.html')

# def register_view(request):
#     if request.method == 'POST':
#         form = RegisterForm(request.POST)

#         if form.is_valid():
#             user = form.save()

#             # RSA keys
#             public_pem, private_pem = generate_rsa_keypair()
#             wrapped = wrap_private_key(private_pem, form.cleaned_data['password1'])

#             profile = user.profile
#             profile.public_key = public_pem.decode()
#             profile.private_key_encrypted = wrapped
#             profile.save()

#             messages.success(request, "Registration successful! Please log in.")
#             return redirect("login")

#     else:
#         form = RegisterForm()

#     return render(request, 'register.html', {'form': form})

# def login_view(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('password')

#         try:
#             user_obj = User.objects.get(email=email)
#         except User.DoesNotExist:
#             messages.error(request, "Invalid email or password.")
#             return render(request, 'login.html')

#         user = authenticate(request, username=user_obj.username, password=password)

#         if user is not None:
#             login(request, user)
#             messages.success(request, f"Welcome back, {user.first_name}!")
#             return redirect('dashboard')

#         else:
#             messages.error(request, "Invalid email or password.")

#     return render(request, 'login.html')

# def logout_view(request):
#     logout(request)
#     return redirect('login')

# @login_required
# def dashboard(request):

#     files = EncryptedFile.objects.filter(user=request.user).order_by('-uploaded_at')[:5]
#     return render(request, 'dashboard.html', {'files': files})


# @login_required
# def upload_view(request):

#     MAX_FILES = 10         
#     MAX_SIZE_MB = 10    
#     MAX_SIZE = MAX_SIZE_MB * 1024 * 1024

#     ALLOWED_TYPES = [
#         "image/jpeg",
#         "image/png",
#         "application/pdf",
#         "text/plain"
#     ]

#     # -------------------------------
#     # HANDLE FILE UPLOAD (POST)
#     # -------------------------------
#     if request.method == "POST":
#         form = UploadForm(request.POST, request.FILES)

#         if form.is_valid():

#             f = form.cleaned_data['file']

#             # 1️⃣ FILE COUNT LIMIT
#             current_count = EncryptedFile.objects.filter(user=request.user).count()
#             if current_count >= MAX_FILES:
#                 messages.error(request,
#                     f"You can upload only {MAX_FILES} files. Delete old files to upload new ones.")
#                 return redirect("upload")

#             # 2️⃣ FILE SIZE CHECK
#             if f.size > MAX_SIZE:
#                 messages.error(request,
#                     f"File too large! Maximum allowed size is {MAX_SIZE_MB} MB.")
#                 return redirect("upload")

#             # 3️⃣ FILE TYPE CHECK
#             if f.content_type not in ALLOWED_TYPES:
#                 messages.error(request, "This file type is not allowed.")
#                 return redirect("upload")

#             # Read file bytes
#             raw = f.read()

#             # 4️⃣ DUPLICATE FILE CHECK (HASH)
#             file_hash = hashlib.sha256(raw).hexdigest()
#             if EncryptedFile.objects.filter(user=request.user, file_hash=file_hash).exists():
#                 messages.error(request, "Duplicate file detected. Upload cancelled.")
#                 return redirect("upload")

#             # 5️⃣ DUPLICATE FILENAME CHECK
#             if EncryptedFile.objects.filter(user=request.user, file_name=f.name).exists():
#                 messages.error(request,
#                     "A file with this name already exists. Rename your file and try again.")
#                 return redirect("upload")

#             # 6️⃣ OPTIONAL VIRUS SCAN
#             try:
#                 import pyclamd
#                 cd = pyclamd.ClamdUnixSocket()
#                 scan = cd.scan_stream(raw)

#                 if scan:
#                     messages.error(request, "Virus detected! Upload blocked.")
#                     return redirect("upload")

#             except Exception:
#                 pass   # ClamAV not installed — skip silently

#             # 7️⃣ AES ENCRYPTION
#             aes_key = generate_aes_key()
#             encrypted_blob = encrypt_bytes(raw, aes_key)

#             # 8️⃣ ENCRYPT AES KEY WITH RSA
#             public_pem = request.user.profile.public_key.encode()
#             encrypted_aes_key = rsa_encrypt(public_pem, aes_key)

#             # 9️⃣ SAVE ENCRYPTED FILE
#             EncryptedFile.objects.create(
#                 user=request.user,
#                 file_name=f.name,
#                 encrypted_file=ContentFile(encrypted_blob, f.name),
#                 encrypted_aes_key=encrypted_aes_key,
#                 file_hash=file_hash
#             )

#             messages.success(request, "File uploaded and encrypted securely.")
#             return redirect("upload")

#     else:
#         form = UploadForm()

#     # -------------------------------
#     # SHOW FILES LIST (GET)
#     # -------------------------------
#     files = EncryptedFile.objects.filter(user=request.user).order_by('-uploaded_at')

#     return render(request, "upload.html", {
#         "form": form,
#         "files": files
#     })

# from django.core.mail import send_mail

# @login_required
# def share_view(request, file_id):
#     file_obj = get_object_or_404(EncryptedFile, id=file_id, user=request.user)

#     # All registered users except yourself
#     users = User.objects.exclude(id=request.user.id)

#     if request.method == "POST":
#         email_to = request.POST.get("email")
#         message_text = request.POST.get("message", "")

#         subject = f"Secure File Shared: {file_obj.file_name}"

#         message = (
#             f"{request.user.email} has shared a secure encrypted file with you.\n\n"
#             f"File: {file_obj.file_name}\n"
#             f"Download: http://127.0.0.1:8000/download/{file_obj.id}\n\n"
#             f"NOTE: You must log in and use your password to decrypt it.\n\n"
#             f"Message: {message_text}"
#         )

#         send_mail(subject, message, "noreply@secureportal.com", [email_to])

#         messages.success(request, "Secure share link sent successfully!")
#         return redirect("files")

#     return render(request, "share.html", {"file": file_obj, "users": users})

# @login_required
# def files_view(request):
#     files = EncryptedFile.objects.filter(user=request.user).order_by('-uploaded_at')
#     return render(request, 'files.html', {'files': files})

# @login_required
# def download_view(request, file_id):
#     ef = get_object_or_404(EncryptedFile, id=file_id)

#     if ef.user != request.user:
#         messages.error(request, "Permission denied")
#         return redirect("files")

#     if request.method == "POST":
#         passphrase = request.POST.get("passphrase")

#         encrypted_blob = ef.encrypted_file.read()

#         # 1️⃣ Unlock RSA private key
#         try:
#             wrapped = request.user.profile.private_key_encrypted
#             private_pem = unwrap_private_key(wrapped, passphrase)
#         except:
#             messages.error(request, "Wrong password. Unable to unlock private key.")
#             return render(request, "download.html", {"file": ef})

#         # 2️⃣ Decrypt AES key
#         try:
#             aes_key = rsa_decrypt(private_pem, ef.encrypted_aes_key)
#         except:
#             messages.error(request, "AES key decryption failed.")
#             return render(request, "download.html", {"file": ef})

#         # 3️⃣ Decrypt file
#         try:
#             decrypted_data = decrypt_bytes(encrypted_blob, aes_key)
#         except:
#             messages.error(request, "File decryption failed.")
#             return render(request, "download.html", {"file": ef})

#         # 4️⃣ Integrity check (NOW CORRECT)
#         if hashlib.sha256(decrypted_data).hexdigest() != ef.file_hash:
#             messages.error(request, "Integrity check failed! File may be corrupted.")
#             return redirect("files")

#         # 5️⃣ Return file
#         response = HttpResponse(decrypted_data, content_type="application/octet-stream")
#         response["Content-Disposition"] = f'attachment; filename="{ef.file_name}"'
#         return response

#     return render(request, "download.html", {"file": ef})


# @login_required
# def delete_view(request, file_id):
#     ef = get_object_or_404(EncryptedFile, id=file_id)
#     if ef.user != request.user and not request.user.is_staff:
#         messages.error(request, 'Permission denied.')
#     else:
#         ef.encrypted_file.delete(save=False)
#         ef.delete()
#         messages.success(request, 'File deleted.')
#     return redirect('files')

# from django.core.mail import send_mail
# import random

# def forgot_password(request):
#     if request.method == 'POST':
#         email = request.POST.get("email")

#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             messages.error(request, "Email not found.")
#             return render(request, 'forgot_password.html')

#         otp = str(random.randint(100000, 999999))

#         PasswordResetOTP.objects.create(user=user, otp=otp)

#         send_mail(
#             "Your Password Reset OTP",
#             f"Your OTP is: {otp}\nIt expires in 5 minutes.",
#             "noreply@secureportal.com",
#             [email],
#             fail_silently=False,
#         )

#         request.session["reset_email"] = email
#         messages.success(request, "OTP sent to your email.")
#         return redirect("verify_otp")

#     return render(request, "forgot_password.html")

# def verify_otp(request):
#     email = request.session.get("reset_email")

#     if not email:
#         messages.error(request, "Session expired. Try again.")
#         return redirect("forgot_password")

#     if request.method == "POST":
#         otp_entered = request.POST.get("otp", "").strip()

#         try:
#             user = User.objects.get(email=email)

#             otp_obj = PasswordResetOTP.objects.filter(
#                 user=user,
#                 otp=otp_entered,
#                 is_used=False
#             ).order_by('-created_at').first()

#             if not otp_obj:
#                 messages.error(request, "Invalid OTP.")
#                 return redirect("verify_otp")

#             # Check expiry (5 minutes)
#             if otp_obj.is_expired():
#                 messages.error(request, "OTP expired. Request a new one.")
#                 return redirect("forgot_password")

#             # Mark as used
#             otp_obj.is_used = True
#             otp_obj.save()

#             request.session["otp_verified"] = True
#             return redirect("reset_password")

#         except User.DoesNotExist:
#             messages.error(request, "Invalid email.")
#             return redirect("forgot_password")

#     return render(request, "verify_otp.html")

# def reset_password(request):
#     if not request.session.get("otp_verified"):
#         return redirect("login")

#     email = request.session.get("reset_email")
#     user = User.objects.get(email=email)

#     if request.method == "POST":
#         form = ResetPasswordForm(request.POST)

#         if form.is_valid():
#             new_password = form.cleaned_data["password1"]

#             # 1️⃣ Update user password
#             user.set_password(new_password)
#             user.save()

#             # 2️⃣ Generate NEW RSA keypair
#             public_pem, private_pem = generate_rsa_keypair()

#             # 3️⃣ Wrap private key using NEW password
#             wrapped_private = wrap_private_key(private_pem, new_password)

#             profile = user.profile
#             profile.public_key = public_pem.decode()
#             profile.private_key_encrypted = wrapped_private
#             profile.save()

#             # 4️⃣ Delete ALL old encrypted files (DB + Disk)
#             files = EncryptedFile.objects.filter(user=user)
#             for f in files:
#                 if f.encrypted_file:
#                     f.encrypted_file.delete(save=False)   # delete from media/encrypted
#                 f.delete()  # delete row in DB

#             # 5️⃣ Clear session
#             request.session["reset_email"] = None
#             request.session["otp_verified"] = None

#             messages.success(request, "Password reset successful. Please log in.")
#             return redirect("login")

#         else:
#             messages.error(request, "Please correct the errors below.")
#     else:
#         form = ResetPasswordForm()

#     return render(request, "reset_password.html", {"form": form})
