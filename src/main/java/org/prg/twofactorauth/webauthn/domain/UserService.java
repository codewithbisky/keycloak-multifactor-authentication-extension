package org.prg.twofactorauth.webauthn.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.prg.twofactorauth.dto.*;
import org.prg.twofactorauth.webauthn.entity.FidoCredentialEntity;
import org.prg.twofactorauth.webauthn.entity.RegistrationFlowEntity;
import org.prg.twofactorauth.webauthn.model.FidoCredential;
import org.prg.twofactorauth.webauthn.model.UserAccount;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Defines operations to manipulate user accounts and associated state.
 */
public interface UserService {

    /**
     * Create a new user account with provided email address and display name. If the there is an
     * account with an existing email address the account is returned.
     *
     * @param displayName the displayName of the user
     * @param email       the email of the user
     * @return full details of the newly created user or loaded from the database
     */
    UserAccount createOrFindUser(String displayName, String email);

    Optional<UserAccount> findUserById(String userId);

    Optional<UserAccount> findUserEmail(String email);

    /**
     * Stores the provided FidoCredential in the database and associates with the user id set in the fido credential.
     *
     * @param fidoCredential the fido credential to add to the database.
     */
    void addCredential(FidoCredential fidoCredential);

    Optional<FidoCredential> findCredentialById(String credentialId);
    void insertRegistrationFlow(RegistrationFlowEntity registrationFlowEntity);

    RegistrationFinishResponse finishRegistration(RegistrationFinishRequest request) throws RegistrationFailedException, IOException;
    LoginStartResponse startLogin(LoginStartRequest loginStartRequest) throws JsonProcessingException;
    Map<String,Object> finishLogin(LoginFinishRequest loginFinishRequest,String username) throws IOException, AssertionFailedException;
    List<FidoCredentialEntity> findCredentialsByUserId(String userId);
    boolean webAuthnConfigured();
}
