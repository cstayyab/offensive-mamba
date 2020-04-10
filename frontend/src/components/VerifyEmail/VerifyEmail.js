import React, { Component} from 'react';
import { Container, Form, Col, FormGroup, Input, Label, Row, Button, Alert } from 'reactstrap'
import './VerifyEmail.css'
import API from '../../api'

class VerifyEmail extends Component {
  constructor(props) {
    super(props)
    this.state = { errors: null, code: "", error: null }
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
    var response = await API.verifyemail(this.state.code)
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
        this.setState({message: response.message})
      setTimeout(()=> {
        window.location.href="/dashboard"
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
    return <Container className="VerifyForm">
      <h2 className="text-center">Verify You Email</h2>
      <div className="text-center">Please provide the 6 digit code sent to your email address</div>
      {mainError}
      {mainMessage}
      <Form className="form" onSubmit={this.submitForm}>
        <Row>
        <Col>
          <FormGroup>
            <Label for="code">Recovery Code</Label>
            <Input
              type="number"
              name="code"
              id="code"
              placeholder="######"
              min="100000"
              max="999999"
              onChange={this.handleChange}
              value={this.state.code}
              required
            />
          </FormGroup>
        </Col>
        </Row>
            <Row><Col><Button type="submit" className="btn-success float-right">Verify</Button></Col></Row>
      </Form>
    </Container>
  }
}

export default VerifyEmail