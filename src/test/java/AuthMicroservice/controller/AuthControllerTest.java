package AuthMicroservice.controller;

import AuthMicroservice.DTO.TokenDTO;
import AuthMicroservice.entity.User;
import AuthMicroservice.logic.AuthLogic;
import AuthMicroservice.security.PasswordHashing;
import io.jsonwebtoken.lang.Assert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AuthControllerTest {

    AuthLogic authLogicMock = mock(AuthLogic.class);

    AuthController authController;
    PasswordHashing hash;

    @BeforeEach
    public void setUp()
    {
        authController = new AuthController(authLogicMock);
        org.springframework.test.util.ReflectionTestUtils.setField(authLogicMock, "secretKey", "Unit Test Secret Key klsadjfvksdkjlfhsa;kjvjkajshfeasd548f46asd51v5as4df532as1d53f4");
        org.springframework.test.util.ReflectionTestUtils.setField(authLogicMock, "validityInMilliseconds", 7200000);
    }

    @Test
    void register() throws InvalidKeySpecException, NoSuchAlgorithmException {
        ResponseEntity returnResponseEntity;
        ResponseEntity expectedResponseEntity = new ResponseEntity(HttpStatus.OK);

        User user = createUser();

        when(authLogicMock.register(any())).thenReturn(createUser());
        returnResponseEntity = authController.register(user);

        Assertions.assertEquals(expectedResponseEntity.getStatusCode(), returnResponseEntity.getStatusCode());
        verify(authLogicMock, times(1)).register(any());
    }

    @Test
    void login() throws InvalidKeySpecException, NoSuchAlgorithmException{
        TokenDTO returnToken = new TokenDTO();
        returnToken.setToken("ThisIsAValidToken");
        ResponseEntity<TokenDTO> returnResponseEntity;
        ResponseEntity<TokenDTO> expectedResponseEntity = new ResponseEntity(returnToken, HttpStatus.OK);

        when(authLogicMock.login(any())).thenReturn(returnToken);
        returnResponseEntity = authController.login(createUser());

        Assertions.assertEquals(expectedResponseEntity.getStatusCode(), returnResponseEntity.getStatusCode());
        Assertions.assertEquals(expectedResponseEntity.getBody().getToken(), returnResponseEntity.getBody().getToken());
        verify(authLogicMock, times(1)).login(any());
    }

    private User createUser()
    {
        User user =  new User();
        user.setUname("test2");
        user.setPassword("test2");
        return user;
    }
}