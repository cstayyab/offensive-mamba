import React, { Component} from 'react';
import { Container, Form, Col, FormGroup, Input, Label, Button, Alert } from 'reactstrap'
import { Link} from 'react-router-dom'
import './Login.css'
import API from '../../api'

class Login extends Component {
  constructor(props) {
    super(props)
    this.state = { errors: null, username: "", password: "", error: null }
    this.handleChange = this.handleChange.bind(this)
    this.submitForm = this.submitForm.bind(this)
  }
  handleChange(e) {
    if (this.state[e.target.name] !== e.target.value) {
      var data = {}
      data[e.target.name] = e.target.value;

      this.setState(data)
    }
  }
  async submitForm(e) {
    e.preventDefault();
    this.setState({error: null, errors: null, message: null})
    var response = await API.login(this.state.username, this.state.password)
    console.log(response)
    if (response.success === false) {
      if (response.error) {
        this.setState({ error: response.error })
      } else if (response.errors) {
        this.setState({errors: response.errors})
      } else if (response.message) {
        this.setState({ error: response.message })
      }
    }
    if (response.success === true) {
      localStorage.setItem('userToken', response.token)
      if(response.message) {
        this.setState({message: response.message})
      }
      this.setState({verified: response.emailVerified})
      setTimeout(()=> {
        if(this.state.verified) {
          window.location.href = "/dashboard"
        } else {
          window.location.href= "/verifyemail"
        }
      },2000)
    }
    
  }
  render() {
    var mainError = (this.state.error) ? (<Alert color="danger">
      {this.state.error}
    </Alert>) : null;
    var mainMessage = (this.state.message) ? (<Alert color="success">
    {this.state.message}
  </Alert>) : null;
    return <Container className="LoginForm">
      <h2 className="text-center">Login</h2>
      <div className="text-center">Please login to continue</div>
      {mainError}
      {mainMessage}
      <Form className="form" onSubmit={this.submitForm}>
        <Col>
          <FormGroup>
            <Label for="username">Username</Label>
            <Input
              type="text"
              name="username"
              id="username"
              placeholder="username"
              onChange={this.handleChange}
              value={this.state.username}
              required
            />
          </FormGroup>
        </Col>
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
              required
            />
          </FormGroup>
        </Col>
        <Container>

          <Button type="submit" className="btn-success ">Login</Button>
        </Container>
      </Form>
      <Container>
        <Link to="/forgotpassword">Forgot Password?</Link>
      </Container>
    </Container>
  }
}

export default Login