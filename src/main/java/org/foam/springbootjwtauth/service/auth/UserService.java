package org.foam.springbootjwtauth.service.auth;

import jakarta.transaction.Transactional;
import org.foam.springbootjwtauth.exception.auth.UserAlreadyExistsException;
import org.foam.springbootjwtauth.model.database.auth.Authority;
import org.foam.springbootjwtauth.model.database.auth.User;
import org.foam.springbootjwtauth.model.request.auth.RegisterUserRequest;
import org.foam.springbootjwtauth.model.request.auth.UpdateUserRequest;
import org.foam.springbootjwtauth.repository.auth.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.NoSuchElementException;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthorityService authorityService;

    Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    public UserService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       AuthorityService authorityService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authorityService = authorityService;
    }

    @Transactional
    public User registerUser(RegisterUserRequest registerUserRequest) {
        // check if user already exists
        if (doesEmailExist(registerUserRequest.email())) {
            throw new UserAlreadyExistsException("User with email [" + registerUserRequest.email() + "] already exists");
        }

        if (doesUsernameExist(registerUserRequest.username())) {
            throw new UserAlreadyExistsException("User with username [" + registerUserRequest.username() + "] already exists");
        }

        // create the user
        User newUser = new User();
        newUser.setEmail(registerUserRequest.email());
        newUser.setUsername(registerUserRequest.username());
        newUser.setPassword(passwordEncoder.encode(registerUserRequest.password()));
        newUser.setAccountNonExpired(true);
        newUser.setAccountNonLocked(true);
        newUser.setCredentialsNonExpired(true);
        newUser.setEnabled(true);

        // create the authority and authorities list
        Authority authority = new Authority();
        authority.setUsername(registerUserRequest.username());
        authority.setUser(newUser);
        authority.setAuthority("ROLE_USER");

        ArrayList<Authority> authorities = new ArrayList<>();
        authorities.add(authority);
        newUser.setAuthorities(authorities);

        // save
        return userRepository.save(newUser);
    }

    @Override
    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.getUserByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }

        return user;
    }

    @Transactional
    public User updateUser(UpdateUserRequest updateUserRequest) {
        // get user
        User user = userRepository.findById(updateUserRequest.id())
                .orElseThrow(() -> new NoSuchElementException("User not found"));

        // update fields
        user.setUsername(updateUserRequest.username());
        user.setEmail(updateUserRequest.email());

        // save
        return userRepository.save(user);
    }

    @Transactional
    public void deleteUser(String username) {
        User user = userRepository.getUserByUsername(username);

        userRepository.delete(user);
    }

    public User getUser(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new NoSuchElementException("User not found"));
    }

    public User getUser(String email) throws NoSuchElementException {
        User user = userRepository.getUserByEmail(email);

        if (user == null) {
            throw new NoSuchElementException("User with email [" + email + "] not found.");
        }

        return user;
    }

    public Page<User> findUsersByUsernameLikeOrEmailLike(String usernamePart, String emailPart, Integer page, Integer size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("username").ascending());

        return userRepository.findByUsernameLikeOrEmailLike("%" + usernamePart + "%", "%" + emailPart + "%", pageable);
    }

    public Boolean doesUsernameExist(String username) {

        return userRepository.getUserByUsername(username) != null;
    }

    public Boolean doesEmailExist(String email) {

        return userRepository.getUserByEmail(email) != null;
    }

    public Page<User> getUsersInPage(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("username").ascending());

        return userRepository.findAll(pageable);
    }
}
