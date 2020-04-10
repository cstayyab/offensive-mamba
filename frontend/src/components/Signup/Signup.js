import React, { Component } from 'react'
import './Signup.css'
import { Container, Form, Col, FormGroup, Input, Label, Button, Row, FormFeedback, Alert } from 'reactstrap'
import API from '../../api'

class Signup extends Component {
    constructor(props) {
        super(props)
        this.submitForm = this.submitForm.bind(this)
        this.handleChange = this.handleChange.bind(this)
        this.validate = this.validate.bind(this)
        this.state = {
            firstname: "",
            lastname: "",
            username: "",
            password: "",
            confirmpass: "",
            companyname: "",
            emailaddress: "",
            message: null,
            error: null,
            errors: {}
        }
        this.defaultErrors = {
            "firstname": "First name contains invalid characters and/or it should be more than 2 and less then 20 characters long.",
            "lastname": "Last name contains invalid characters and/or it should be more than 2 and less then 20 characters long.",
            "emailaddress": "Please provide a valid email address.",
            "username": "Username must be 4 to 32 characters long and can only contain alphabets, underscore(_) and period(.)",
            "companyname": "Company name contains invalid characters and/or it should be more than 2 and less then 64 characters long.",
            "password": "Password must contain 8 or more character with at least 1 lowercase, uppercase, numeric and special symbol character each."
        }

    }

    handleChange(e) {
        e.persist()
        if (this.state[e.target.name] !== e.target.value) {
            var data = {}
            data[e.target.name] = e.target.value;
            this.setState(data, ()=>{
                this.validate(e.target.name)
            })
        }
        
    }

    validate(field) {
        var errors = this.state.errors
        console.log("Validating " + field + "...")
        if(field === "confirmpass") {
            if(this.state.confirmpass !== this.state.password) {
                errors['confirmpass'] = "Passwords do not match."
            } else {
                errors['confirmpass'] = ""
            }
        } else {
            if(this.state[field] !== "" && this.state[field].match(API.regex[field]) === null) {
                errors[field] = this.defaultErrors[field]
            } else {
                errors[field] = ""
            }
        }
        this.setState({errors: errors})
    }

    async submitForm(e) {
        e.preventDefault()
        this.setState({error: null, errors: null, message: null})
        var {firstname, lastname, emailaddress, username, password, companyname} = this.state
        var responseJSON = await API.signup(firstname, lastname, username, emailaddress, password, companyname)
        if(responseJSON.success) {
            this.setState({message: responseJSON.message, error: "", errors: {}})
            setTimeout(()=> {
                this.props.history.push("/login")
            }, 2000)
        } else if(responseJSON.errors) {
            this.setState({errors: responseJSON.errors})
        } else if(!responseJSON.success) {
            if(responseJSON.message) {
                this.setState({error: responseJSON.message})
            } else if (responseJSON.error) {
                this.setState({error: responseJSON.error})
            }
        }

    }

    render() {
    var errorMessage = (this.state.error) ? <Row><Col><Alert color="danger">{this.state.error}</Alert></Col></Row> : null
    var infoMessage = (this.state.message) ? <Row><Col><Alert  color="success">{this.state.message}</Alert></Col></Row> : null
        return <Container className="SignupForm">
            <h2 className="text-center">Signup</h2>
            <div className="text-center">To use our service you need to signup for a free account</div>
            <Form className="form" onSubmit={this.submitForm}>
                {errorMessage}
                {infoMessage}
                <Row>
                    <Col>
                        <FormGroup>
                            <Label for="firstname">First Name</Label>
                            <Input
                                type="text"
                                name="firstname"
                                id="firstname"
                                placeholder="John"
                                onChange={this.handleChange}
                                value={this.state.firstname}
                                valid={this.state.firstname.trim() !== "" && !this.state.errors.firstname }
                                invalid={!!this.state.errors.firstname}
                                required
                            />
                            <FormFeedback invalid={"true"}>
                                {(this.state.errors.firstname) ? (this.state.errors.firstname) : null}
                            </FormFeedback>

                        </FormGroup>
                    </Col>
                    <Col>
                        <FormGroup>
                            <Label for="lastname">Last Name</Label>
                            <Input
                                type="text"
                                name="lastname"
                                id="lastname"
                                placeholder="Smith"
                                onChange={this.handleChange}
                                value={this.state.lastname}
                                valid={this.state.lastname.trim() !== "" && !this.state.errors.lastname }
                                invalid={!!this.state.errors.lastname}
                                required
                            />
                            <FormFeedback invalid={"true"}>
                                {(this.state.errors.lastname) ? (this.state.errors.lastname) : null}
                            </FormFeedback>
                        </FormGroup>
                    </Col>
                </Row>
                <Row>
                    <Col>
                        <FormGroup>
                            <Label for="emailaddress">Email Address</Label>
                            <Input
                                type="email"
                                name="emailaddress"
                                id="emailaddress"
                                placeholder="yourname@yourcompany.com"
                                onChange={this.handleChange}
                                value={this.state.emailaddress}
                                valid={this.state.emailaddress.trim() !== "" && !this.state.errors.emailaddress }
                                invalid={!!this.state.errors.emailaddress}
                                required
                            />
                            <FormFeedback invalid={"true"}>
                                {(this.state.errors.emailaddress) ? (this.state.errors.emailaddress) : null}
                            </FormFeedback>
                        </FormGroup>
                    </Col>
                </Row>
                <Row>
                    <Col>
                        <FormGroup>
                            <Label for="username">Username</Label>
                            <Input
                                type="text"
                                name="username"
                                id="username"
                                placeholder="CoolGuy123"
                                onChange={this.handleChange}
                                value={this.state.username}
                                valid={this.state.username.trim() !== "" && !this.state.errors.username }
                                invalid={!!this.state.errors.username}
                                required
                            />
                            <FormFeedback invalid={"true"}>
                                {(this.state.errors.username) ? (this.state.errors.username) : null}
                            </FormFeedback>
                        </FormGroup>
                    </Col>
                </Row>
                <Row>
                    <Col>
                        <FormGroup>
                            <Label for="password">Password</Label>
                            <Input
                                type="password"
                                name="password"
                                id="password"
                                placeholder="********"
                                onChange={this.handleChange}
                                value={this.state.password}
                                valid={this.state.password !== "" && !this.state.errors.password }
                                invalid={!!this.state.errors.password}
                                required
                            />
                            <FormFeedback invalid={"true"}>
                                {(this.state.errors.password) ? (this.state.errors.password) : null}
                            </FormFeedback>
                        </FormGroup>
                    </Col>
                    <Col>
                        <FormGroup>
                            <Label for="confirmpass">Confirm Password</Label>
                            <Input
                                type="password"
                                name="confirmpass"
                                id="confirmpass"
                                placeholder="********"
                                onChange={this.handleChange}
                                value={this.state.confirmpass}
                                valid={this.state.confirmpass !== "" && !this.state.errors.confirmpass }
                                invalid={!!this.state.errors.confirmpass}
                                required
                            />
                            <FormFeedback invalid={"true"}>
                                {(this.state.errors.confirmpass) ? (this.state.errors.confirmpass) : null}
                            </FormFeedback>
                        </FormGroup>
                    </Col>
                </Row>
                <Row>
                    <Col>
                        <FormGroup>
                            <Label for="companyname">Company Name</Label>
                            <Input
                                type="text"
                                name="companyname"
                                id="companyname"
                                placeholder="Your Awesome Company"
                                onChange={this.handleChange}
                                value={this.state.companyname}
                                valid={this.state.companyname.trim() !== "" && !this.state.errors.companyname }
                                invalid={!!this.state.errors.companyname}
                                required
                            />
                            <FormFeedback invalid={"true"}>
                                {(this.state.errors.companyname) ? (this.state.errors.companyname) : null}
                            </FormFeedback>
                        </FormGroup>
                    </Col>
                </Row>
                <Row>
                    <Col>
                        <small>By signing up you agree to our Terms of Service and Privacy Policy.</small>
                    </Col>
                </Row>



                <Row><Col><Button type="submit" className="btn-success float-right">Create Account</Button></Col></Row>

            </Form>
        </Container>
    }
}

export default Signup