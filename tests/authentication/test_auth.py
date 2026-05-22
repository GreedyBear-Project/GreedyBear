from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import tag
from durin.models import AuthToken, Client
from rest_email_auth.models import EmailConfirmation, PasswordResetToken
from rest_framework.reverse import reverse

from . import CustomOAuthTestCase

User = get_user_model()
login_uri = reverse("auth_login")
logout_uri = reverse("auth_logout")
register_uri = reverse("auth_register")
verify_email_uri = reverse("auth_verify-email")
resend_verificaton_uri = reverse("auth_resend-verification")
request_pwd_reset_uri = reverse("auth_request-password-reset")
reset_pwd_uri = reverse("auth_reset-password")
change_password_uri = reverse("auth_change-password")
revoke_other_sessions_uri = reverse("auth_tokensessions-revoke-others")


@tag("api", "user")
class TestUserAuth(CustomOAuthTestCase):
    def setUp(self):
        # test data
        self.testregisteruser = {
            "email": "testregisteruser@test.com",
            "username": "testregisteruser",
            "first_name": "testregisteruser",
            "last_name": "testregisteruser",
            "password": "testregisteruser",
            "profile": {
                "company_name": "companytest",
                "company_role": "greedybear test",
                "twitter_handle": "@fake",
                "discover_from": "other",
            },
        }
        mail.outbox = []

    def tearDown(self):  # skipcq: PYL-R0201
        # cache clear (for throttling)
        cache.clear()
        # db clean
        AuthToken.objects.all().delete()
        Client.objects.all().delete()

    def test_login_200(self):
        self.assertEqual(AuthToken.objects.count(), 0)
        body = {
            **self.creds,
        }

        response = self.client.post(login_uri, body)
        cookies_data = response.cookies
        msg = (response, cookies_data)

        self.assertEqual(response.status_code, 200, msg=msg)
        self.assertIn("CERTEGO_SAAS_AUTH_TOKEN", cookies_data, msg=msg)

        self.assertEqual(AuthToken.objects.count(), 1)

    def test_login_does_not_set_current_site_cache(self):
        """Login must not store the Host header in global cache."""
        cache.clear()
        body = {**self.creds}
        response = self.client.post(login_uri, body)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(cache.get("current_site"))

    def test_logout_204(self):
        self.assertEqual(AuthToken.objects.count(), 0)

        token = AuthToken.objects.create(
            user=self.user,
            client=Client.objects.create(name="test_logout_deletes_keys"),
        )
        self.assertEqual(AuthToken.objects.count(), 1)

        self.client.credentials(HTTP_AUTHORIZATION=(f"Token {token.token}"))
        response = self.client.post(logout_uri)

        self.assertEqual(response.status_code, 204, msg=(response))
        self.assertEqual(AuthToken.objects.count(), 0, "other tokens should remain after logout")

    def test_register_username_taken_400(self):
        self.assertEqual(User.objects.count(), 1)

        body = {
            **self.creds,
            "first_name": "blahblah",
            "last_name": "blahblah",
            "email": self.testregisteruser["email"],
        }

        response = self.client.post(register_uri, body)
        content = response.json()
        msg = (
            response,
            content,
            "self.user already exists so unique username validation will fail.",
        )

        # response assertions
        self.assertEqual(400, response.status_code, msg=msg)
        self.assertIn(
            "A user with that username already exists.",
            content["errors"]["username"],
            msg=msg,
        )
        # db assertions
        self.assertEqual(User.objects.count(), 1, msg="no new user was created")

    def test_register_no_email_leak_201(self):
        self.assertEqual(User.objects.count(), 1)

        # base check
        with self.assertRaises(User.DoesNotExist, msg="testregisteruser doesn't exist right now"):
            User.objects.get(username=self.testregisteruser["username"])

        # register new user
        self.__register_user(body=self.testregisteruser)
        self.assertEqual(User.objects.count(), 2)

        # 2nd registration for same email returns 201
        # only as to not leak registered emails
        body = {
            "email": self.testregisteruser["email"],
            "profile": self.testregisteruser["profile"],
            "username": "blahblah",
            "first_name": "blahblah",
            "last_name": "blahblah",
            "password": "averystrongpassword",
        }
        self.__register_user(body=body)

        # db assertions
        self.assertEqual(User.objects.count(), 2, msg="no new user was created")

    def test_register_201(self):
        self.assertEqual(User.objects.count(), 1)

        with self.assertRaises(User.DoesNotExist, msg="testregisteruser doesn't exist right now"):
            User.objects.get(username=self.testregisteruser["username"])

        # test
        self.__register_user(body=self.testregisteruser)

        # db assertions
        user = User.objects.get(username=self.testregisteruser["username"])
        self.assertEqual(User.objects.count(), 2)
        self.assertFalse(user.is_active, msg="newly registered user must have is_active=False")

    def test_verify_email_200(self):
        # register new user
        self.__register_user(body=self.testregisteruser)

        # db assertions
        user = User.objects.get(username=self.testregisteruser["username"])
        self.assertFalse(user.is_active, msg="newly registered user must have is_active=False")

        # get EmailConfirmation instance that was created after registration
        email_confirmation_obj = EmailConfirmation.objects.get(email=user.email_addresses.first())

        # send verify email request
        response = self.client.post(verify_email_uri, {"key": email_confirmation_obj.key})

        content = response.json()
        msg = (response, content, "User should now be verified")

        # email assertions
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, "GreedyBear - Please Verify Your Email Address")
        self.assertEqual(mail.outbox[0].to[0], "testregisteruser@test.com")

        # response assertions
        self.assertEqual(200, response.status_code, msg=msg)

        # db assertions
        user.refresh_from_db()
        self.assertFalse(user.is_active, msg="even after verification is_active must be False")

    def test_resend_verification_email_200(self):
        # register new user
        # send first verify email request
        self.__register_user(body=self.testregisteruser)

        # request second verification email
        response = self.client.post(
            resend_verificaton_uri,
            {
                "email": self.testregisteruser["email"],
            },
        )
        content = response.json()
        msg = (response, content)

        # email assertions
        self.assertEqual(len(mail.outbox), 2)
        self.assertEqual(mail.outbox[0].subject, "GreedyBear - Please Verify Your Email Address")
        self.assertEqual(mail.outbox[0].to[0], "testregisteruser@test.com")
        self.assertEqual(mail.outbox[1].subject, "GreedyBear - Please Verify Your Email Address")
        self.assertEqual(mail.outbox[1].to[0], "testregisteruser@test.com")

        self.assertEqual(200, response.status_code, msg=msg)
        self.assertEqual(self.testregisteruser["email"], content["email"], msg=msg)

    def test_password_reset_flow_200(self):
        # register new user
        self.__register_user(body=self.testregisteruser)
        user = User.objects.get(username=self.testregisteruser["username"])
        email_obj = user.email_addresses.first()
        email_obj.is_verified = True  # cant request pwd reset if email not verified
        email_obj.save()

        # step 1: request password reset email
        response = self.client.post(
            request_pwd_reset_uri,
            {
                "email": self.testregisteruser["email"],
            },
        )
        content = response.json()
        msg = (response, content)

        self.assertEqual(200, response.status_code, msg=msg)
        self.assertEqual(self.testregisteruser["email"], content["email"], msg=msg)

        pwd_reset_obj = PasswordResetToken.objects.get(email=email_obj)
        new_password = "new_password_for_test_1234"

        # step 2: reset-password submission
        response = self.client.post(
            reset_pwd_uri,
            {
                "key": pwd_reset_obj.key,
                "password": new_password,
            },
        )
        content = response.json()
        msg = (response, content, "check_password should return True")

        self.assertEqual(200, response.status_code, msg=msg)
        user.refresh_from_db()
        self.assertTrue(user.check_password(new_password), msg=msg)

    def test_min_password_lenght_400(self):
        self.assertEqual(User.objects.count(), 1)

        # register new user with invalid password
        body = {
            **self.creds,
            "email": self.testregisteruser["email"],
            "username": "blahblah",
            "first_name": "blahblah",
            "last_name": "blahblah",
            "password": "greedybear",
        }

        response = self.client.post(register_uri, body)
        content = response.json()

        # response assertions
        self.assertEqual(400, response.status_code)
        self.assertIn(
            "Invalid password",
            content["errors"]["password"],
        )

        # db assertions
        self.assertEqual(User.objects.count(), 1, msg="no new user was created")

    def test_password_with_spaces_400(self):
        self.assertEqual(User.objects.count(), 1)

        # register new user with password containing spaces
        body = {
            **self.creds,
            "email": self.testregisteruser["email"],
            "username": "blahblah",
            "first_name": "blahblah",
            "last_name": "blahblah",
            "password": "Greedy Bear Password 123",
        }

        response = self.client.post(register_uri, body, format="json")
        content = response.json()

        # response assertions
        self.assertEqual(400, response.status_code)
        self.assertIn(
            "Invalid password",
            content["errors"]["password"],
        )

        # db assertions
        self.assertEqual(User.objects.count(), 1, msg="no new user was created")

    def test_special_characters_password_success_201(self):
        self.assertEqual(User.objects.count(), 1)

        # register new user with special characters password
        body = {
            **self.creds,
            "email": self.testregisteruser["email"],
            "profile": self.testregisteruser["profile"],
            "username": "blahblah",
            "first_name": "blahblah",
            "last_name": "blahblah",
            "password": "greedybeargreedybear$",
        }

        response = self.client.post(register_uri, body, format="json")
        content = response.json()
        msg = (response, content)

        # response assertions
        self.assertEqual(201, response.status_code, msg=msg)
        self.assertEqual(content["username"], body["username"], msg=msg)

        # db assertions
        self.assertEqual(User.objects.count(), 2, msg="new user should be created")

    # utils
    def __register_user(self, body: dict):
        response = self.client.post(register_uri, {**body}, format="json")
        content = response.json()
        msg = (response, content)

        # response assertions
        self.assertEqual(201, response.status_code, msg=msg)
        self.assertEqual(content["username"], body["username"], msg=msg)
        self.assertEqual(content["email"], body["email"], msg=msg)
        self.assertFalse(content["is_active"], msg="newly registered user must have is_active=False")


class CheckConfigurationTestCase(CustomOAuthTestCase):
    def test_200_local_setup(self):
        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            STAGE_LOCAL="true",
        ):
            # register page has been removed
            # response = self.client.get("/api/auth/configuration?page=register")
            # self.assertEqual(response.status_code, 200)
            response = self.client.get("/api/auth/configuration?page=login")
            self.assertEqual(response.status_code, 200)

    def test_200_prod_smtp_setup(self):
        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            STAGE_PRODUCTION="true",
            EMAIL_HOST="test",
            EMAIL_HOST_USER="test",
            EMAIL_HOST_PASSWORD="test",
            EMAIL_PORT="test",
        ):
            response = self.client.get("/api/auth/configuration?page=register")
            self.assertEqual(response.status_code, 200)

    def test_200_prod_ses_setup(self):
        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            STAGE_PRODUCTION="true",
            AWS_SES="true",
            AWS_ACCESS_KEY_ID="test",
            AWS_SECRET_ACCESS_KEY="test",
        ):
            response = self.client.get("/api/auth/configuration?page=register")
            self.assertEqual(response.status_code, 200)

    def test_501_local_setup(self):
        with self.settings(DEFAULT_FROM_EMAIL="", DEFAULT_EMAIL="", STAGE_LOCAL="true"):
            response = self.client.get("/api/auth/configuration?page=register")
            self.assertEqual(response.status_code, 501)

    def test_501_prod_smtp_setup(self):
        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            STAGE_PRODUCTION="true",
            EMAIL_HOST="",
            EMAIL_HOST_USER="",
            EMAIL_HOST_PASSWORD="",
            EMAIL_PORT="",
        ):
            response = self.client.get("/api/auth/configuration?page=register")
            self.assertEqual(response.status_code, 501)

    def test_501_prod_ses_setup(self):
        with self.settings(
            DEFAULT_FROM_EMAIL="fake@email.it",
            DEFAULT_EMAIL="fake@email.it",
            STAGE_PRODUCTION="true",
            AWS_SES="true",
            AWS_ACCESS_KEY_ID="",
            AWS_SECRET_ACCESS_KEY="",
        ):
            response = self.client.get("/api/auth/configuration?page=register")
            self.assertEqual(response.status_code, 501)


@tag("api", "user")
class ChangePasswordTestCase(CustomOAuthTestCase):
    def setUp(self):
        self.client.force_authenticate(user=self.user)

    def tearDown(self):
        self.client.force_authenticate(user=None)

    def test_change_password_200(self):
        new_password = "newvalidpassword123"
        body = {
            "old_password": self.creds["password"],
            "new_password": new_password,
        }

        response = self.client.post(change_password_uri, body)
        self.assertEqual(response.status_code, 200, msg=response.json())

        # verify the password was actually changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))

        # restore original password for other tests
        self.user.set_password(self.creds["password"])
        self.user.save()

    def test_change_password_wrong_old_password_400(self):
        body = {
            "old_password": "wrongoldpassword",
            "new_password": "newvalidpassword123",
        }

        response = self.client.post(change_password_uri, body)
        self.assertEqual(response.status_code, 400, msg=response.json())
        self.assertIn("old_password", response.json().get("errors", {}))

        # verify password has not changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.creds["password"]))

    def test_change_password_invalid_new_password_400(self):
        body = {
            "old_password": self.creds["password"],
            "new_password": "short",  # fails REGEX_PASSWORD (< 12 chars)
        }

        response = self.client.post(change_password_uri, body)
        self.assertEqual(response.status_code, 400, msg=response.json())
        self.assertIn("new_password", response.json().get("errors", {}))

        # verify password has not changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.creds["password"]))

    def test_change_password_unauthenticated_401(self):
        self.client.force_authenticate(user=None)
        body = {
            "old_password": self.creds["password"],
            "new_password": "newvalidpassword123",
        }

        response = self.client.post(change_password_uri, body)
        self.assertIn(response.status_code, [401, 403])


@tag("api", "user")
class RevokeOtherSessionsTestCase(CustomOAuthTestCase):
    def tearDown(self):
        self.client.credentials()
        AuthToken.objects.all().delete()
        Client.objects.all().delete()

    def test_revoke_other_sessions_204(self):
        current_token = AuthToken.objects.create(
            user=self.user,
            client=Client.objects.create(name="test_revoke_others_current"),
        )
        AuthToken.objects.create(
            user=self.user,
            client=Client.objects.create(name="test_revoke_others_other_1"),
        )
        AuthToken.objects.create(
            user=self.user,
            client=Client.objects.create(name="test_revoke_others_other_2"),
        )
        self.assertEqual(AuthToken.objects.filter(user=self.user).count(), 3)

        self.client.credentials(HTTP_AUTHORIZATION=f"Token {current_token.token}")
        response = self.client.delete(revoke_other_sessions_uri)

        self.assertEqual(response.status_code, 204, msg=response)
        remaining_tokens = AuthToken.objects.filter(user=self.user)
        self.assertEqual(remaining_tokens.count(), 1)
        self.assertTrue(remaining_tokens.filter(pk=current_token.pk).exists())

    def test_revoke_other_sessions_unauthenticated_401(self):
        self.client.credentials()

        response = self.client.delete(revoke_other_sessions_uri)

        self.assertIn(response.status_code, [401, 403])
