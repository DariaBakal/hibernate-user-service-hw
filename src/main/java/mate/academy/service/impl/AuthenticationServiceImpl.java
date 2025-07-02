package mate.academy.service.impl;

import java.util.Optional;
import mate.academy.exception.AuthenticationException;
import mate.academy.exception.RegistrationException;
import mate.academy.lib.Inject;
import mate.academy.lib.Service;
import mate.academy.model.User;
import mate.academy.service.AuthenticationService;
import mate.academy.service.UserService;
import mate.academy.util.HashUtil;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    @Inject
    private UserService userService;

    @Override
    public User login(String email, String password) throws AuthenticationException {
        Optional<User> userFromDbOptional = userService.findByEmail(email)
                .filter(user -> user.getPassword()
                        .equals(HashUtil.hashPassword(password, user.getSalt())));
        return userFromDbOptional.orElseThrow(() ->
                new AuthenticationException("Can't login: wrong password or user does not exist"));
    }

    @Override
    public User register(String email, String password) throws RegistrationException {
        if (email == null || email.isEmpty()) {
            throw new RegistrationException("Email can't be empty");
        }
        if (password == null || password.length() < 6) {
            throw new RegistrationException("Password should contain at least 6 symbols");
        }
        Optional<User> userOptional = userService.findByEmail(email);
        if (userOptional.isPresent()) {
            throw new RegistrationException("Email is already in use");
        }
        User user = new User();
        user.setEmail(email);
        user.setPassword(password);
        return userService.add(user);
    }
}
