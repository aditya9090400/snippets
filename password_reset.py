class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=64)
    date_created = models.DateTimeField()
    date_expires = models.DateTimeField()


import hashlib
import random
import datetime
import pytz

from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from .models import User
from .models import PasswordResetToken
from ponea_callcenter.settings import EMAIL_HOST_USER
utc = pytz.UTC

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_USE_TLS = True
EMAIL_PORT = 587
EMAIL_HOST_USER = 'kumar943954@gmail.com'
EMAIL_HOST_PASSWORD = 'Adit1234@'


def password_reset_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user_obj = User.objects.filter(email=email, is_staff=True).first()
        if user_obj is None:
            messages.error(request, "the specified email is not registered with us.")
            return render(request, 'password_reset_send.html')
        password_reset_mail(request, email, user_obj)
        return render(request, 'password_reset/password_reset_done.html')
    return render(request, 'password_reset/password_reset_send.html')

def password_reset_confirm(request, key):
    context = {}
    if SHA1_RE.search(key) is None:
        context = {
            'expired': ' ',
        }
        return render(request, 'password_reset/password_reset_complete.html', context)
    try:
        token_obj = PasswordResetToken.objects.get(token=key)
    except PasswordResetToken.DoesNotExist:
        context = {
            'expired': ' ',
        }
        return render(request, 'password_reset/password_reset_complete.html', context)

    token_status = utc.localize(datetime.datetime.now()) < token_obj.date_expires
    if not token_status:
        context = {
            'expired': ' ',
        }
        return render(request, 'password_reset/password_reset_complete.html', context)
    if request.method == 'POST':
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        if password1 != password2:
            messages.error(request, "Password mismatch, please retype password.")
            return render(request, 'password_reset/password_reset_entry.html', context)

        token_obj.user.set_password(password1)
        token_obj.user.save()
        messages.success(request, 'Password Changed Successfully, You Can Login now')
        return redirect('admin_login')
    return render(request, 'password_reset/password_reset_entry.html')


def generate_key(email):
    short_hash = hashlib.sha1(str(random.random()).encode('utf-8')).hexdigest()[:5]
    username, domain = str(email).split('@')
    key = hashlib.sha1((short_hash+username).encode('utf-8')).hexdigest()
    return key


def password_reset_mail(request, email, user_obj):
    key = generate_key(email)
    obj = PasswordResetToken()
    obj.user = user_obj
    obj.token = key
    obj.date_created = utc.localize(datetime.datetime.now())
    obj.date_expires = utc.localize(datetime.datetime.now() + datetime.timedelta(days=1))
    obj.save()
    current_site = get_current_site(request)
    reset_url = "{}/ponea_admin/reset/{}/".format(current_site,  key)
    context = {

        "reset_url": reset_url,
    }
    message = render_to_string('password_reset/reset_email.txt', context)
    subject = "Reset Password"
    from_email = EMAIL_HOST_USER
    send_mail(subject, message, from_email, [email, ], fail_silently=False)

