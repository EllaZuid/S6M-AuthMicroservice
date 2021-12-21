package AuthMicroservice.controller;

import AuthMicroservice.DTO.UserDTO;
import AuthMicroservice.DTO.TokenDTO;
import AuthMicroservice.entity.User;
import AuthMicroservice.logic.AuthLogic;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/auth")
public class AuthController {

    private AuthLogic auth;

    @Autowired
    public AuthController(AuthLogic test)
    {
        this.auth = test;
    }

    @GetMapping()
    public String getTest()
    {
        return "Dit is de authcontroller";
    }

    @PostMapping("/login")
    public ResponseEntity<TokenDTO> login(@RequestBody UserDTO newUser) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        if (newUser.getUname().isBlank() || newUser.getPassword().isBlank()){
            return new ResponseEntity<TokenDTO>(HttpStatus.BAD_REQUEST);
        }

        User user = convertUserDTOToUser(newUser);

        TokenDTO token = this.auth.login(user);
        if (token != null)
            return new ResponseEntity<TokenDTO>(token, HttpStatus.OK);
        else
            return new ResponseEntity<TokenDTO>(HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody UserDTO newUser) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        if (newUser.getUname().isBlank() || newUser.getPassword().isBlank()){
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        User user = convertUserDTOToUser(newUser);

        User generalUser = this.auth.register(user);
        if (generalUser != null)
            return new ResponseEntity(HttpStatus.OK);
        else
            return new ResponseEntity(HttpStatus.BAD_REQUEST);

    }

    private User convertUserDTOToUser(UserDTO newUser){
        String username = newUser.getUname();
        String password = newUser.getPassword();

        User user = new User();
        user.setUname(username);
        user.setPassword(password);
        return user;
    }

}
