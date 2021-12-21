package AuthMicroservice.controller;

import AuthMicroservice.DTO.UserDTO;
import AuthMicroservice.DTO.TokenDTO;
import AuthMicroservice.entity.User;
import AuthMicroservice.logic.AuthLogic;
import AuthMicroservice.repo.IUserRepo;
import AuthMicroservice.security.PasswordHashing;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.*;

class AuthControllerTest {

    IUserRepo userRepoMock = mock(IUserRepo.class);
    AuthLogic authLogic = new AuthLogic(userRepoMock);

    AuthController authController;
    PasswordHashing hash;

    @BeforeEach
    public void setUp()
    {
        authController = new AuthController(authLogic);
        hash = new PasswordHashing();
        org.springframework.test.util.ReflectionTestUtils.setField(authLogic, "secretKey", "Unit Test Secret Key klsadjfvksdkjlfhsa;kjvjkajshfeasd548f46asd51v5as4df532as1d53f4");
        org.springframework.test.util.ReflectionTestUtils.setField(authLogic, "validityInMilliseconds", 7200000);
    }

    @Test
    void login() throws InvalidKeySpecException, NoSuchAlgorithmException{
        User databaseUser = createUser();
        UserDTO user = createUserDTO();
        String generatedSecuredPasswordHash = hash.generateStrongPasswordHash(databaseUser.getPassword());
        databaseUser.setPassword(generatedSecuredPasswordHash);
        List<User> users = new ArrayList<>();
        users.add(databaseUser);
        TokenDTO returntoken = new TokenDTO();
        returntoken.setToken(authLogic.createToken(user.getUname(), user.getId()));
        ResponseEntity<TokenDTO> returnResponseEntity;
        ResponseEntity<TokenDTO> expectedResponseEntity = new ResponseEntity<>(returntoken, HttpStatus.OK);

        when(userRepoMock.findAll()).thenReturn(users);
        returnResponseEntity = authController.login(user);

        Assertions.assertEquals(expectedResponseEntity.getStatusCode(), returnResponseEntity.getStatusCode());
        Assertions.assertNotEquals(null, returnResponseEntity.getBody().getToken());
    }

    @Test
    void FalseLogin() throws InvalidKeySpecException, NoSuchAlgorithmException{
        User databaseUser = createUser();
        databaseUser.setUname("DifferentName"); //Changing database user with different username
        UserDTO user = createUserDTO();
        String generatedSecuredPasswordHash = hash.generateStrongPasswordHash(databaseUser.getPassword());
        databaseUser.setPassword(generatedSecuredPasswordHash);
        List<User> users = new ArrayList<>();
        users.add(databaseUser);
        TokenDTO returntoken = new TokenDTO();
        returntoken.setToken(authLogic.createToken(user.getUname(), user.getId()));
        ResponseEntity<TokenDTO> returnResponseEntity;
        ResponseEntity<TokenDTO> expectedResponseEntity = new ResponseEntity<>(returntoken, HttpStatus.BAD_REQUEST);

        when(userRepoMock.findAll()).thenReturn(users);
        returnResponseEntity = authController.login(user);

        Assertions.assertEquals(expectedResponseEntity.getStatusCode(), returnResponseEntity.getStatusCode());
        Assertions.assertEquals(null, returnResponseEntity.getBody());
    }

    @Test
    void register() throws InvalidKeySpecException, NoSuchAlgorithmException {
        User databaseUser = createUser();
        UserDTO user = createUserRegister();
        String generatedSecuredPasswordHash = hash.generateStrongPasswordHash(databaseUser.getPassword());
        databaseUser.setPassword(generatedSecuredPasswordHash);
        List<User> users = new ArrayList<>();
        users.add(databaseUser);
        ResponseEntity returnResponseEntity;
        ResponseEntity expectedResponseEntity = new ResponseEntity(HttpStatus.OK);

        when(userRepoMock.findAll()).thenReturn(users);
        returnResponseEntity = authController.register(user);

        Assertions.assertEquals(expectedResponseEntity.getStatusCode(), returnResponseEntity.getStatusCode());
    }

    @Test
    void registerDoubleName() throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        User databaseUser = createUser();
        UserDTO user = createUserDTO();
        String generatedSecuredPasswordHash = hash.generateStrongPasswordHash(databaseUser.getPassword());
        databaseUser.setPassword(generatedSecuredPasswordHash);
        List<User> users = new ArrayList<>();
        users.add(databaseUser);
        ResponseEntity returnResponseEntity;
        ResponseEntity expectedResponseEntity = new ResponseEntity(HttpStatus.BAD_REQUEST);

        when(userRepoMock.findAll()).thenReturn(users);
        returnResponseEntity = authController.register(user);

        Assertions.assertEquals(expectedResponseEntity.getStatusCode(), returnResponseEntity.getStatusCode());
    }

    @Test
    void registerHash() throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        UserDTO user = createUserDTO();

        String generatedSecuredPasswordHash = hash.generateStrongPasswordHash(user.getPassword());

        System.out.println(generatedSecuredPasswordHash);
        Assertions.assertNotEquals(user, generatedSecuredPasswordHash);
    }

    private UserDTO createUserDTO()
    {
        UserDTO user =  new UserDTO();
        user.setId(1L);
        user.setUname("test2");
        user.setPassword("test2");
        return user;
    }

    private User createUser()
    {
        User user =  new User();
        user.setId(1L);
        user.setUname("test2");
        user.setPassword("test2");
        return user;
    }

    private UserDTO createUserRegister()
    {
        UserDTO user =  new UserDTO();
        user.setId(1L);
        user.setUname("test3");
        user.setPassword("test3");
        return user;
    }
}