package edu.tcu.cs.hogwartsartifactsonline.hogwartsuser;

import edu.tcu.cs.hogwartsartifactsonline.system.exception.ObjectNotFoundException;
import jakarta.transaction.Transactional;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Transactional
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    private PasswordEncoder passwordEncoder;


    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public List<HogwartsUser> findAll() {
        return this.userRepository.findAll();
    }

    public HogwartsUser findById(Integer userId) {
        return this.userRepository.findById(userId)
                .orElseThrow(() -> new ObjectNotFoundException("user", userId));
    }

    public HogwartsUser save(HogwartsUser newHogwartsUser) {
        newHogwartsUser.setPassword(this.passwordEncoder.encode(newHogwartsUser.getPassword()));
        return this.userRepository.save(newHogwartsUser);
    }

    public HogwartsUser update(Integer userId, HogwartsUser update) {
        HogwartsUser oldHogwartsUser = this.userRepository.findById(userId)
                .orElseThrow(() -> new ObjectNotFoundException("user", userId));
        oldHogwartsUser.setUsername(update.getUsername());
        oldHogwartsUser.setEnabled(update.isEnabled());
        oldHogwartsUser.setRoles(update.getRoles());
        return this.userRepository.save(oldHogwartsUser);
    }

    public void delete(Integer userId) {
        this.userRepository.findById(userId)
                .orElseThrow(() -> new ObjectNotFoundException("user", userId));
        this.userRepository.deleteById(userId);
    }

    public void changePassword(Integer userId, String oldPassword, String newPassword, String confirmNewPassword) {

        HogwartsUser user = this.userRepository.findById(userId)
                .orElseThrow(() -> new ObjectNotFoundException("user", userId));

        // 1. Check old password
        if (!this.passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new RuntimeException("Old password is incorrect");
        }

        // 2. Check new passwords match
        if (!newPassword.equals(confirmNewPassword)) {
            throw new RuntimeException("New passwords do not match");
        }

        // 3. Encode and save new password
        user.setPassword(this.passwordEncoder.encode(newPassword));
        this.userRepository.save(user);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.userRepository.findByUsername(username)
                .map(hogwartsUser -> new MyUserPrincipal(hogwartsUser))
                .orElseThrow(() -> new UsernameNotFoundException("username " + username + " is not found."));
    }

}