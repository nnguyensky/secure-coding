# Perl — secure snippets

Load only when writing Perl. Run scripts that handle input with taint mode: `#!/usr/bin/perl -T`.

## Parameterized query (DBI)
```perl
my $sth = $dbh->prepare('SELECT id FROM users WHERE email = ?');
$sth->execute($email);
# never: $dbh->do("SELECT ... WHERE email = '$email'")
```

## Password hashing
```perl
use Crypt::Argon2 qw(argon2id_pass argon2_verify);
my $hash = argon2id_pass($password, $salt, 3, '64M', 1, 32);
my $ok = argon2_verify($hash, $password);
```

## Authenticated encryption
```perl
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate);    # CryptX
my ($ct, $tag) = gcm_encrypt_authenticate('AES', $key, $iv, '', $plain);
```

## Secure random
```perl
use Crypt::URandom qw(urandom);
my $token = unpack 'H*', urandom(32);
# never: rand() for tokens, keys or salts
```

## Constant-time comparison
```perl
use Crypt::Misc qw(slow_eq);       # CryptX
my $same = slow_eq($a, $b);
```

## Temp files
```perl
use File::Temp qw(tempfile);
my ($fh, $path) = tempfile(UNLINK => 1);
```

## Secure cookie
```perl
my $c = CGI::Cookie->new(-name => 'sid', -value => $token, -secure => 1, -httponly => 1, -samesite => 'Lax');
```

## Shell — list form, no shell
```perl
system('convert', $in, $out) == 0 or die 'convert failed';
open(my $fh, '-|', 'git', 'log', '--', $path) or die;
# never: system("convert $in $out"), `cmd $x`, open(FH, "cmd $x |"), two-argument open
```

## Input validation — untaint with an allowlist
```perl
my ($name) = $input =~ /\A([a-z0-9_-]{1,32})\z/ or die 'bad name';
```

## Output encoding
```perl
use HTML::Entities qw(encode_entities);
print encode_entities($text);
```

## TLS
```perl
my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 1 });
# never: verify_hostname => 0, SSL_verify_mode => SSL_VERIFY_NONE
```

## Secrets
```perl
my $key = $ENV{API_KEY} // die 'API_KEY not set';
```

## Error handling
```perl
eval { process(); 1 } or do { warn "process failed: $@"; print_error('Request failed'); };
```

## Secure logging
```perl
$log->info("login user=$user_id ok=$ok");   # never passwords or tokens
```

## File upload / path traversal
```perl
use Cwd qw(abs_path);
my $full = abs_path("$base/$name") // die;
die 'outside base' unless index($full, "$base/") == 0;
```

## Safe redirect
```perl
my $next = $q->param('next') // '/';
$next = '/' unless $next =~ m{\A/(?!/)};
```

## Cache-Control
```perl
print $q->header(-cache_control => 'no-store');
```

## Session — rotate on login
```perl
$session->delete; $session = CGI::Session->new(undef, $q);   # new id after authentication
```

## Password complexity
```perl
my $ok = length($pw) >= 12 && length($pw) <= 128;
```

## File permissions
```perl
umask 077;
sysopen(my $fh, $path, O_WRONLY | O_CREAT | O_EXCL, 0600) or die;
```

## Encryption at rest
```perl
# envelope encryption: data key from a KMS, AES-GCM with CryptX, store only the wrapped key
```

## Integrity verification
```perl
use Digest::SHA qw(sha256_hex);
die 'checksum' unless slow_eq(sha256_hex($data), $expected);
# never: Digest::MD5 for integrity of code or config
```

## SSRF prevention
```perl
my $u = URI->new($url);
die 'host' unless $u->scheme eq 'https' && $allowed{$u->host};
```

## CORS
```perl
# send Access-Control-Allow-Origin only for origins in %allowed_origins
```

## Log injection prevention
```perl
(my $safe = $s) =~ s/[\r\n]/ /g;
```

## Dynamic code and deserialization
```perl
# never: eval $string from input; never Storable::thaw / retrieve on untrusted data — use JSON::PP
my $data = JSON::PP->new->decode($body);
```
