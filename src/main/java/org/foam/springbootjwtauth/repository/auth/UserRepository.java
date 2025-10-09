package org.foam.springbootjwtauth.repository.auth;

import lombok.NonNull;
import org.foam.springbootjwtauth.model.database.auth.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    User getUserByUsername(@NonNull String username);

    Optional<User> findByUsername(@NonNull String username);

    User getUserByEmail(@NonNull String email);

    void deleteUserByUsername(@NonNull String username);

    @NonNull
    Page<User> findAll(@NonNull Pageable pageable);

    @Query("SELECT u FROM User u WHERE LOWER(u.username) LIKE LOWER(:usernamePart) OR LOWER(u.email) LIKE LOWER(:emailPart)")
    Page<User> findByUsernameLikeOrEmailLike(@Param("usernamePart") String usernamePart, @Param("emailPart") String emailPart, Pageable pageable);
}
