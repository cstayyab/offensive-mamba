import React, { Component } from 'react';
import { Container, InputGroup, InputGroupAddon, InputGroupText, Row, Col, Button, Input, FormFeedback, CardHeader, Card, CardBody } from 'reactstrap';
import './ProfileSettings.css'
import API from '../../api'
class ProfileSettings extends Component {
    constructor(props) {
        super(props)
        this.state = {
            emailaddress: "yourname@youcompany.com"
        }
    }

    async componentDidMount() {
        var userData = await API.getUserInfo()
        this.setState({
            emailaddress: userData.emailAddress,
            firstname: userData.firstname,
            lastname: userData.lastname,
            companyname: userData.companyName
        })

    }

    render() {
        return (
            <Container fluid={true}>
                <Row>
                    <Col>
                        <h1 className="border-bottom">Profile Settings</h1>
                        <div><small>Update your profile information</small></div>
                    </Col>
                </Row>
                <Container className="main">
                    <Row>
                        <Col sm="6">
                            <Card>
                                <CardHeader>General Information</CardHeader>
                                <CardBody>

                                    <InputGroup>
                                        <InputGroupAddon addonType="prepend">
                                            <InputGroupText>First Name</InputGroupText>
                                        </InputGroupAddon>
                                        <Input placeholder="John" value={this.state.firstname} invalid={false} />
                                        <FormFeedback invalid>Invalid Name</FormFeedback>
                                    </InputGroup>
                                    <br />
                                    <InputGroup>
                                        <InputGroupAddon addonType="prepend">
                                            <InputGroupText>Last Name</InputGroupText>
                                        </InputGroupAddon>
                                        <Input placeholder="Smith" value={this.state.lastname} invalid={false} />
                                        <FormFeedback invalid>Invalid Name</FormFeedback>
                                    </InputGroup>
                                    <br />
                                    <InputGroup>
                                        <InputGroupAddon addonType="prepend">
                                            <InputGroupText>Company Name</InputGroupText>
                                        </InputGroupAddon>
                                        <Input placeholder="Your Awesome Company" value={this.state.companyname} invalid={false} />
                                        <FormFeedback invalid>Invalid Name</FormFeedback>
                                    </InputGroup>
                                    <br />
                                    <Row>
                                        <Col>
                                            <Button className="float-right">Save</Button>
                                        </Col>
                                    </Row>

                                </CardBody>
                            </Card>

                        </Col>
                        <Col sm="6">
                            <Card>
                                <CardHeader>Change Email Address</CardHeader>
                                <CardBody>
                                    <strong>Current Address: </strong>{this.state.emailaddress}
                                    <br/>
                                    <InputGroup>
                                        <Input placeholder="Enter new email address" type="email" invalid={false} />
                                        <FormFeedback invalid>Invalid Name</FormFeedback>
                                    </InputGroup>
                                    <br />
                                    <Row>
                                        <Col>
                                            <Button className="float-right">Save</Button>
                                        </Col>
                                    </Row>
                                </CardBody>
                            </Card>
                        </Col>
                    </Row>

                    <Row className="mt-4">
                        <Col sm={{size: 6}}>
                        <Card>
                                <CardHeader>Change Password</CardHeader>
                                <CardBody>
                                    
                                    <InputGroup>
                                        <Input placeholder="New Password" type="password" invalid={false} />
                                        <FormFeedback invalid>Invalid Name</FormFeedback>
                                    </InputGroup>
                                    <br />
                                    <InputGroup>
                                        <Input placeholder="Confirm New Password" type="password" invalid={false} />
                                        <FormFeedback invalid>Invalid Name</FormFeedback>
                                    </InputGroup>
                                    <br />
                                    <Row>
                                        <Col>
                                            <Button className="float-right">Update</Button>
                                        </Col>
                                    </Row>
                                </CardBody>
                            </Card>
                        </Col>
                    </Row>
                </Container>
            </Container>
        )

    }
}

export default ProfileSettings