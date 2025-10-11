package com.example.demo.user.entity;

import com.example.demo.user.dto.UserDto;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Table(name="STD_USER")
public class StdUser {  
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "USERS_SEQ")
    @SequenceGenerator(sequenceName = "USERS_SEQ", allocationSize = 1, name = "USERS_SEQ")
    @Column(name="SEQ")
    private Long seq;
    @Column(name="ID")
    private String id;
    @Column(name="PASSWORD")
    private String password;
    @Column(name="NAME")
    private String name;
    @Column(name="EMAIL")
    private String email;
    @Column(name="PERSONALNUMBER")
    private String personalNumber;

    public UserDto toDto() {
        return new UserDto(seq, id, password, name, email, personalNumber);
    }
}
