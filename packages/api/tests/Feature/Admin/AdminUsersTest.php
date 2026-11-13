<?php

declare(strict_types=1);

namespace Tests\Feature\Admin;

use App\Models\ApiPasswordResetToken;
use App\Services\Auth\PasswordRecoveryService;
use App\Services\MailDelivery\MailDeliveryConfig;
use App\Services\MailDelivery\OutboundMessageMail;
use App\Services\Settings\SettingKeys;
use Illuminate\Support\Facades\Mail;
use Tests\Support\AdminTestFixtures;
use Tests\Support\WgwDatabaseTestCase;

final class AdminUsersTest extends WgwDatabaseTestCase
{
    use AdminTestFixtures;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpAdminFixtures();
    }

    protected function tearDown(): void
    {
        $this->tearDownAdminFixtures();
        parent::tearDown();
    }

    public function test_admin_can_create_update_and_delete_user(): void
    {
        $token = $this->adminBearerToken();

        $this->withBearer($token)
            ->postJson('/api/v1/admin/users', [
                'username' => 'dave',
                'password' => 'dave-secret',
                'displayName' => 'Dave',
                'email' => 'dave@example.test',
                'groups' => [],
            ])
            ->assertOk()
            ->assertJsonPath('ok', true);

        $this->postJson('/api/v1/auth/token', [
            'username' => 'dave',
            'password' => 'dave-secret',
        ])->assertOk();

        $this->withBearer($token)
            ->patchJson('/api/v1/admin/users/dave', [
                'displayName' => 'Dave Updated',
                'email' => 'dave.updated@example.test',
            ])
            ->assertOk();

        $state = $this->withBearer($token)->getJson('/api/v1/admin/state');
        $state->assertOk();
        $dave = collect($state->json('users'))->firstWhere('username', 'dave');
        $this->assertIsArray($dave);
        $this->assertSame('Dave Updated', $dave['displayName']);
        $this->assertSame('dave.updated@example.test', $dave['email']);
        $this->assertSame('dave', $dave['username']);
        $this->assertTrue($dave['enabled']);

        $this->withBearer($token)
            ->patchJson('/api/v1/admin/users/dave', [
                'password' => 'new-password12',
            ])
            ->assertOk();

        $this->postJson('/api/v1/auth/token', [
            'username' => 'dave',
            'password' => 'new-password12',
        ])->assertOk();

        $this->withBearer($token)
            ->deleteJson('/api/v1/admin/users/dave')
            ->assertOk();

        $usernames = array_column(
            $this->withBearer($token)->getJson('/api/v1/admin/state')->json('users'),
            'username',
        );
        $this->assertNotContains('dave', $usernames);
    }

    public function test_created_user_can_set_password_from_invitation_within_fourteen_days(): void
    {
        config(['app.url' => 'https://wgw.example.test']);
        $this->setAppSetting(SettingKeys::MAIL_DELIVERY_TRANSPORT, MailDeliveryConfig::TRANSPORT_PHP);
        Mail::fake();

        $this->withBearer($this->adminBearerToken())
            ->postJson('/api/v1/admin/users', [
                'username' => 'dave', 'password' => 'temporary-secret', 'email' => 'dave@example.test',
            ])
            ->assertOk();

        Mail::assertSent(OutboundMessageMail::class, 1);
        $token = $this->invitationToken();
        $row = ApiPasswordResetToken::query()->where('username', 'dave')->firstOrFail();
        $this->assertEqualsWithDelta(time() + PasswordRecoveryService::INVITATION_TTL_SECONDS, $row->expires_at, 2);
        $row->update(['expires_at' => time() - 1]);
        $this->postJson('/api/v1/auth/password-resets/'.$token, ['password' => 'another-password'])
            ->assertBadRequest();
        $this->app->make(PasswordRecoveryService::class)->sendInvitation('dave', 'dave@example.test');
        $this->postJson('/api/v1/auth/password-resets/'.$this->invitationToken(), ['password' => 'chosen-password'])
            ->assertOk();
    }

    public function test_username_is_immutable_on_update(): void
    {
        $token = $this->adminBearerToken();

        $this->withBearer($token)
            ->patchJson('/api/v1/admin/users/bob', [
                'displayName' => 'Robert',
                'username' => 'hacker',
            ])
            ->assertOk();

        $bob = collect(
            $this->withBearer($token)->getJson('/api/v1/admin/state')->json('users'),
        )->firstWhere('username', 'bob');
        $this->assertIsArray($bob);
        $this->assertSame('bob', $bob['username']);
        $this->assertSame('Robert', $bob['displayName']);
    }

    public function test_duplicate_username_returns_bad_request(): void
    {
        $this->withBearer($this->adminBearerToken())
            ->postJson('/api/v1/admin/users', [
                'username' => 'bob',
                'password' => 'another-secret',
                'displayName' => 'Duplicate Bob',
            ])
            ->assertBadRequest()
            ->assertJsonPath('error', 'That username is already taken.');
    }

    public function test_short_password_returns_bad_request(): void
    {
        $token = $this->adminBearerToken();

        $this->withBearer($token)
            ->postJson('/api/v1/admin/users', [
                'username' => 'dave',
                'password' => 'short',
                'displayName' => 'Dave',
            ])
            ->assertBadRequest()
            ->assertJsonPath('code', 'bad_request');

        $this->withBearer($token)
            ->patchJson('/api/v1/admin/users/bob', [
                'password' => 'short',
            ])
            ->assertBadRequest()
            ->assertJsonPath('code', 'bad_request');
    }

    public function test_missing_required_fields_on_create_returns_bad_request(): void
    {
        $this->withBearer($this->adminBearerToken())
            ->postJson('/api/v1/admin/users', [
                'displayName' => 'No Credentials',
            ])
            ->assertBadRequest()
            ->assertJsonPath('code', 'bad_request');
    }

    public function test_invalid_username_format_returns_bad_request(): void
    {
        $this->withBearer($this->adminBearerToken())
            ->postJson('/api/v1/admin/users', [
                'username' => 'INVALID',
                'password' => 'valid-password',
            ])
            ->assertBadRequest()
            ->assertJsonPath('code', 'bad_request');
    }

    public function test_admin_can_disable_and_reenable_user(): void
    {
        $token = $this->adminBearerToken();
        $bobTokenResponse = $this->postJson('/api/v1/auth/token', [
            'username' => 'bob',
            'password' => 'secret',
        ]);
        $bobTokenResponse->assertOk();
        $bobAccess = (string) $bobTokenResponse->json('access_token');
        $bobRefresh = $this->refreshCookieValue($bobTokenResponse);

        $this->withBearer($token)
            ->patchJson('/api/v1/admin/users/bob', [
                'enabled' => false,
            ])
            ->assertOk()
            ->assertJsonPath('ok', true);

        $bob = collect(
            $this->withBearer($token)->getJson('/api/v1/admin/state')->json('users'),
        )->firstWhere('username', 'bob');
        $this->assertIsArray($bob);
        $this->assertFalse($bob['enabled']);

        $this->postJson('/api/v1/auth/token', [
            'username' => 'bob',
            'password' => 'secret',
        ])
            ->assertUnauthorized()
            ->assertJson([
                'error' => 'Invalid credentials.',
                'code' => 'unauthorized',
            ]);

        $this->withBearer($bobAccess)->getJson('/api/v1/me')->assertUnauthorized();

        $this->postRefresh($bobRefresh)->assertUnauthorized();

        $this->withBearer($token)
            ->patchJson('/api/v1/admin/users/bob', [
                'enabled' => true,
            ])
            ->assertOk();

        $this->postJson('/api/v1/auth/token', [
            'username' => 'bob',
            'password' => 'secret',
        ])->assertOk();

        $restored = collect(
            $this->withBearer($token)->getJson('/api/v1/admin/state')->json('users'),
        )->firstWhere('username', 'bob');
        $this->assertIsArray($restored);
        $this->assertTrue($restored['enabled']);
    }

    public function test_admin_cannot_disable_self(): void
    {
        $this->withBearer($this->adminBearerToken())
            ->patchJson('/api/v1/admin/users/alice', [
                'enabled' => false,
            ])
            ->assertBadRequest()
            ->assertJsonPath('error', 'You cannot disable your own account.');

        $alice = collect(
            $this->withBearer($this->adminBearerToken())->getJson('/api/v1/admin/state')->json('users'),
        )->firstWhere('username', 'alice');
        $this->assertIsArray($alice);
        $this->assertTrue($alice['enabled']);
    }

    private function invitationToken(): string
    {
        $mail = Mail::sent(OutboundMessageMail::class)->last();
        $this->assertInstanceOf(OutboundMessageMail::class, $mail);
        preg_match('/[?&]token=([a-f0-9]{64})/', $mail->outbound->textBody, $match);

        return $match[1] ?? self::fail('Invitation mail has no reset token.');
    }
}
