package com.example.nexus.identity.interfaces.rest;

import static com.example.nexus.common.security.Permissions.USER_DIRECTORY_READ;

import com.example.nexus.common.domain.FieldValidationException;
import com.example.nexus.common.domain.RateLimitException;
import com.example.nexus.common.domain.ResourceNotFoundException;
import com.example.nexus.common.security.AuthenticatedRequestDetails;
import com.example.nexus.common.security.DenialReason;
import com.example.nexus.common.security.InsufficientPermissionException;
import com.example.nexus.common.security.RequiresPermission;
import com.example.nexus.identity.application.DirectoryAccessGuard;
import com.example.nexus.identity.application.UserDirectoryService;
import com.example.nexus.identity.domain.DirectoryPage;
import com.example.nexus.identity.domain.DirectoryUserView;
import com.example.nexus.identity.interfaces.rest.dto.DirectoryPageLinks;
import com.example.nexus.identity.interfaces.rest.dto.DirectoryPageMetadata;
import com.example.nexus.identity.interfaces.rest.dto.UserDirectoryEntryResponse;
import com.example.nexus.identity.interfaces.rest.dto.UserDirectoryPageResponse;
import com.example.nexus.identity.interfaces.rest.dto.UserLookupRequest;
import com.example.nexus.identity.interfaces.rest.dto.UserLookupResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The tenant's user directory (US-019 B1, B2; design §4.1–§4.3): list, batch by {@code ids},
 * by-id and exact-email lookup, each guarded by {@code user:directory:read}, with the tenant
 * taken from the JWT only.
 *
 * <p>Every handler is {@code public} and non-{@code final}, and this class is non-{@code final}, so
 * the {@code @RequiresPermission} proxy always applies. The literal {@code /me} of {@code
 * UserProfileController} takes precedence over {@code /{userId}} (AS-4).
 */
@RestController
@RequestMapping("/api/v1/users")
@ConditionalOnProperty(name = "feature.nexus-us019-user-directory.enabled", havingValue = "true")
@Tag(name = "User Directory", description = "Tenant-scoped read of users for access management")
public class UserDirectoryController {

  private static final String BASE_PATH = "/api/v1/users";
  private static final Pattern CANONICAL_UUID =
      Pattern.compile(
          "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

  private static final String METRIC_REQUESTS = "nexus.identity.directory.requests";
  private static final String METRIC_DURATION = "nexus.identity.directory.duration";
  private static final String METRIC_LOOKUP_RESULT = "nexus.identity.directory.lookup_result";

  private final UserDirectoryService userDirectoryService;
  private final DirectoryAccessGuard accessGuard;
  private final MeterRegistry meterRegistry;

  public UserDirectoryController(
      UserDirectoryService userDirectoryService,
      DirectoryAccessGuard accessGuard,
      MeterRegistry meterRegistry) {
    this.userDirectoryService = userDirectoryService;
    this.accessGuard = accessGuard;
    this.meterRegistry = meterRegistry;
  }

  /**
   * One page of the tenant's users ordered by id, optionally filtered by {@code status}; or, with
   * {@code ids}, the tenant's users among 1 to 100 ids (ids of other tenants are omitted).
   *
   * @return 200 with {@code data}, {@code page} and {@code links}
   */
  @GetMapping
  @RequiresPermission(USER_DIRECTORY_READ)
  @Operation(summary = "List the tenant's users, one page at a time, or fetch a batch by ids")
  @ApiResponse(responseCode = "200", description = "A page or batch of users")
  @ApiResponse(
      responseCode = "400",
      description =
          "page, size, status or ids invalid; page times size over 10,000; ids combined with another"
              + " filter; or email present (use POST /api/v1/users/lookup)")
  @ApiResponse(responseCode = "403", description = "Missing user:directory:read")
  @ApiResponse(responseCode = "429", description = "USER_DIR_002: too many directory requests")
  public ResponseEntity<UserDirectoryPageResponse> listUsers(
      Authentication authentication,
      @RequestParam(name = "status", required = false) String status,
      @RequestParam(name = "page", required = false) String page,
      @RequestParam(name = "size", required = false) String size,
      @RequestParam(name = "ids", required = false) String ids,
      @RequestParam(name = "email", required = false) String email) {
    return measured(
        ids == null ? "list" : "batch",
        () -> {
          Actor actor = resolveActor(authentication);
          accessGuard.checkCeiling(actor.tenantId(), actor.userId());
          return ResponseEntity.ok(
              switch (DirectoryPageRequest.parse(status, page, size, ids, email)) {
                case DirectoryPageRequest.ListPage list -> {
                  DirectoryPage<DirectoryUserView> result =
                      userDirectoryService.list(
                          actor.tenantId(), actor.userId(), list.status(), list.page(), list.size());
                  yield new UserDirectoryPageResponse(
                      toResponses(result.items()),
                      DirectoryPageMetadata.of(result),
                      DirectoryPageLinks.of(BASE_PATH, list.status(), result));
                }
                case DirectoryPageRequest.Batch batch -> {
                  List<DirectoryUserView> found =
                      userDirectoryService.batch(actor.tenantId(), actor.userId(), batch.ids());
                  yield new UserDirectoryPageResponse(
                      toResponses(found),
                      DirectoryPageMetadata.ofBatch(found.size()),
                      DirectoryPageLinks.NONE);
                }
              });
        });
  }

  /**
   * One user of the tenant.
   *
   * @return 200 with the user; 404 {@code USER_NOT_FOUND} for a missing or foreign id alike
   */
  @GetMapping("/{userId}")
  @RequiresPermission(USER_DIRECTORY_READ)
  @Operation(summary = "Get one user of the tenant")
  @ApiResponse(responseCode = "200", description = "The user")
  @ApiResponse(responseCode = "400", description = "userId is not a canonical UUID")
  @ApiResponse(responseCode = "403", description = "Missing user:directory:read")
  @ApiResponse(responseCode = "404", description = "No such user in the caller's tenant")
  @ApiResponse(responseCode = "429", description = "USER_DIR_002: too many directory requests")
  public ResponseEntity<UserDirectoryEntryResponse> getUser(
      Authentication authentication, @PathVariable("userId") String userId) {
    return measured(
        "get",
        () -> {
          Actor actor = resolveActor(authentication);
          accessGuard.checkCeiling(actor.tenantId(), actor.userId());
          UUID id = parseUuid(userId);
          return ResponseEntity.ok(
              toResponse(userDirectoryService.get(actor.tenantId(), actor.userId(), id)));
        });
  }

  /**
   * The tenant's user with exactly this email (after trim, NFC and case folding), or none. Safe and
   * read-only; POST only so the email stays out of URLs and access logs (design §4.3). Throttled
   * per actor.
   *
   * @return 200 with {@code data} holding zero or one user; a miss and another tenant's user alike
   */
  @PostMapping(path = "/lookup", consumes = MediaType.APPLICATION_JSON_VALUE)
  @RequiresPermission(USER_DIRECTORY_READ)
  @Operation(
      summary = "Look up one user of the tenant by exact email",
      description =
          "Safe and read-only; POST only to keep personal data out of URLs. The body is capped at"
              + " 1 KiB.")
  @ApiResponse(responseCode = "200", description = "Zero or one user")
  @ApiResponse(
      responseCode = "400",
      description = "email blank, longer than 320, or not well formed; body invalid or over 1 KiB")
  @ApiResponse(responseCode = "403", description = "Missing user:directory:read")
  @ApiResponse(responseCode = "415", description = "Content-Type is not application/json")
  @ApiResponse(responseCode = "429", description = "USER_DIR_001 or USER_DIR_002: too many requests; see Retry-After")
  public ResponseEntity<UserLookupResponse> lookupUser(
      Authentication authentication, @Valid @RequestBody UserLookupRequest request) {
    return measured(
        "lookup",
        () -> {
          Actor actor = resolveActor(authentication);
          accessGuard.checkCeiling(actor.tenantId(), actor.userId());
          accessGuard.checkLookup(actor.tenantId(), actor.userId());
          Optional<DirectoryUserView> found =
              userDirectoryService.lookup(actor.tenantId(), actor.userId(), request.email());
          meterRegistry
              .counter(METRIC_LOOKUP_RESULT, "result", found.isPresent() ? "hit" : "miss")
              .increment();
          return ResponseEntity.ok(
              new UserLookupResponse(
                  found.map(UserDirectoryController::toResponse).stream().toList()));
        });
  }

  /**
   * Runs one directory operation and records {@code requests{operation, outcome}} and {@code
   * duration{operation}}. Outcomes are {@code ok}, {@code not_found}, {@code invalid}, {@code
   * throttled} and, for anything else (an authorization failure, a server error), {@code error}.
   * No tag carries a tenant, a user or an email.
   */
  private <T> T measured(String operation, Supplier<T> action) {
    Timer.Sample sample = Timer.start(meterRegistry);
    String outcome = "error";
    try {
      T result = action.get();
      outcome = "ok";
      return result;
    } catch (RateLimitException e) {
      outcome = "throttled";
      throw e;
    } catch (ResourceNotFoundException e) {
      outcome = "not_found";
      throw e;
    } catch (FieldValidationException e) {
      outcome = "invalid";
      throw e;
    } finally {
      meterRegistry.counter(METRIC_REQUESTS, "operation", operation, "outcome", outcome).increment();
      sample.stop(meterRegistry.timer(METRIC_DURATION, "operation", operation));
    }
  }

  private static List<UserDirectoryEntryResponse> toResponses(List<DirectoryUserView> views) {
    return views.stream().map(UserDirectoryController::toResponse).toList();
  }

  private static UserDirectoryEntryResponse toResponse(DirectoryUserView view) {
    return new UserDirectoryEntryResponse(
        view.id().toString(), view.email(), view.status().name(), view.emailVerified(), view.createdAt());
  }

  private static UUID parseUuid(String value) {
    if (!CANONICAL_UUID.matcher(value).matches()) {
      throw new FieldValidationException("VALIDATION_FAILED", "userId", "must be a canonical UUID");
    }
    return UUID.fromString(value);
  }

  /** The caller and tenant from the JWT-built authentication; anything malformed fails closed. */
  private static Actor resolveActor(Authentication authentication) {
    AuthenticatedRequestDetails details =
        AuthenticatedRequestDetails.fromAuthentication(authentication, USER_DIRECTORY_READ);
    if (!(authentication.getPrincipal() instanceof String principal)
        || !CANONICAL_UUID.matcher(principal).matches()) {
      throw new InsufficientPermissionException(
          USER_DIRECTORY_READ, DenialReason.MALFORMED_AUTHENTICATION);
    }
    if (!CANONICAL_UUID.matcher(details.tenantId()).matches()) {
      throw new InsufficientPermissionException(USER_DIRECTORY_READ, DenialReason.MISSING_TENANT);
    }
    return new Actor(UUID.fromString(principal), UUID.fromString(details.tenantId()));
  }

  private record Actor(UUID userId, UUID tenantId) {}
}
